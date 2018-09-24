/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hbase.regionserver.handler;

import edu.umd.cs.findbugs.annotations.Nullable;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.client.TableDescriptor;
import org.apache.hadoop.hbase.executor.EventHandler;
import org.apache.hadoop.hbase.executor.EventType;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.Region;
import org.apache.hadoop.hbase.regionserver.RegionServerServices;
import org.apache.hadoop.hbase.regionserver.RegionServerServices.PostOpenDeployContext;
import org.apache.hadoop.hbase.regionserver.RegionServerServices.RegionStateTransitionContext;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.hbase.shaded.protobuf.generated.RegionServerStatusProtos.RegionStateTransition.TransitionCode;

/**
 * Handles opening of a region on a region server.
 * <p/>
 * Just done the same thing with the old {@link OpenRegionHandler}, with some modifications on
 * fencing and retrying. But we need to keep the {@link OpenRegionHandler} as is to keep compatible
 * with the zk less assignment for 1.x, otherwise it is not possible to do rolling upgrade.
 */
@InterfaceAudience.Private
public class AssignRegionHandler extends EventHandler {

  private static final Logger LOG = LoggerFactory.getLogger(AssignRegionHandler.class);

  private final RegionInfo regionInfo;

  private final TableDescriptor tableDesc;

  private final long masterSystemTime;

  public AssignRegionHandler(RegionServerServices server, RegionInfo regionInfo,
      @Nullable TableDescriptor tableDesc, long masterSystemTime, EventType eventType) {
    super(server, eventType);
    this.regionInfo = regionInfo;
    this.tableDesc = tableDesc;
    this.masterSystemTime = masterSystemTime;
  }

  private RegionServerServices getServer() {
    return (RegionServerServices) server;
  }

  private void cleanUpAndReportFailure(IOException error) throws IOException {
    LOG.warn("Failed to open region {}, will report to master", regionInfo.getRegionNameAsString(),
      error);
    RegionServerServices rs = getServer();
    rs.getRegionsInTransitionInRS().remove(regionInfo.getEncodedNameAsBytes(), Boolean.TRUE);
    if (!rs.reportRegionStateTransition(new RegionStateTransitionContext(TransitionCode.FAILED_OPEN,
      HConstants.NO_SEQNUM, masterSystemTime, regionInfo))) {
      throw new IOException(
        "Failed to report failed open to master: " + regionInfo.getRegionNameAsString());
    }
  }

  @Override
  public void process() throws IOException {
    RegionServerServices rs = getServer();
    String encodedName = regionInfo.getEncodedName();
    byte[] encodedNameBytes = regionInfo.getEncodedNameAsBytes();
    String regionName = regionInfo.getRegionNameAsString();
    Region onlineRegion = rs.getRegion(encodedName);
    if (onlineRegion != null) {
      LOG.warn("Received OPEN for the region:{}, which is already online", regionName);
      // Just follow the old behavior, do we need to call reportRegionStateTransition? Maybe not?
      // For normal case, it could happen that the rpc call to schedule this handler is succeeded,
      // but before returning to master the connection is broken. And when master tries again, we
      // have already finished the opening. For this case we do not need to call
      // reportRegionStateTransition any more.
      return;
    }
    LOG.info("Open {}", regionName);
    Boolean previous = rs.getRegionsInTransitionInRS().putIfAbsent(encodedNameBytes, Boolean.TRUE);
    if (previous != null) {
      if (previous) {
        // The region is opening and this maybe a retry on the rpc call, it is safe to ignore it.
        LOG.info("Receiving OPEN for the region:{}, which we are already trying to OPEN" +
          " - ignoring this new request for this region.", regionName);
      } else {
        // The region is closing. This is possible as we will update the region state to CLOSED when
        // calling reportRegionStateTransition, so the HMaster will think the region is offline,
        // before we actually close the region, as reportRegionStateTransition is part of the
        // closing process.
        LOG.info("Receiving OPEN for the region:{}, which we are trying to close, try again later",
          regionName);
        // TODO: backoff
        rs.getExecutorService().delayedSubmit(this, 1, TimeUnit.SECONDS);
      }
      return;
    }
    HRegion region;
    try {
      TableDescriptor htd =
        tableDesc != null ? tableDesc : rs.getTableDescriptors().get(regionInfo.getTable());
      if (htd == null) {
        throw new IOException("Missing table descriptor for " + regionName);
      }
      // pass null for the last parameter, which used to be a CancelableProgressable, as now the
      // opening can not be interrupted by a close request any more.
      region = HRegion.openHRegion(regionInfo, htd, rs.getWAL(regionInfo), rs.getConfiguration(),
        rs, null);
    } catch (IOException e) {
      cleanUpAndReportFailure(e);
      return;
    }
    rs.postOpenDeployTasks(new PostOpenDeployContext(region, masterSystemTime));
    rs.addRegion(region);
    LOG.info("Opened {}", regionName);
    Boolean current = rs.getRegionsInTransitionInRS().remove(regionInfo.getEncodedNameAsBytes());
    if (current == null) {
      // Should NEVER happen, but let's be paranoid.
      LOG.error("Bad state: we've just opened a region that was NOT in transition. Region={}",
        regionName);
    } else if (!current) {
      // Should NEVER happen, but let's be paranoid.
      LOG.error("Bad state: we've just opened a region that was closing. Region={}", regionName);
    }
  }

  @Override
  protected void handleException(Throwable t) {
    LOG.warn("Fatal error occured while opening region {}, aborting...",
      regionInfo.getRegionNameAsString(), t);
    getServer().abort(
      "Failed to open region " + regionInfo.getRegionNameAsString() + " and can not recover", t);
  }

  public static AssignRegionHandler create(RegionServerServices server, RegionInfo regionInfo,
      TableDescriptor tableDesc, long masterSystemTime) {
    EventType eventType;
    if (regionInfo.isMetaRegion()) {
      eventType = EventType.M_RS_CLOSE_META;
    } else if (regionInfo.getTable().isSystemTable() ||
      (tableDesc != null && tableDesc.getPriority() >= HConstants.ADMIN_QOS)) {
      eventType = EventType.M_RS_OPEN_PRIORITY_REGION;
    } else {
      eventType = EventType.M_RS_OPEN_REGION;
    }
    return new AssignRegionHandler(server, regionInfo, tableDesc, masterSystemTime, eventType);
  }
}