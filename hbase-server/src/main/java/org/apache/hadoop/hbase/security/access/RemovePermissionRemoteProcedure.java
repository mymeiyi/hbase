/*
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
package org.apache.hadoop.hbase.security.access;

import java.io.IOException;

import org.apache.hadoop.hbase.ServerName;
import org.apache.hadoop.hbase.master.procedure.MasterProcedureEnv;
import org.apache.hadoop.hbase.master.procedure.RSProcedureDispatcher;
import org.apache.hadoop.hbase.master.procedure.ServerProcedureInterface;
import org.apache.hadoop.hbase.master.procedure.ServerRemoteProcedure;
import org.apache.hadoop.hbase.procedure2.ProcedureStateSerializer;
import org.apache.hadoop.hbase.procedure2.RemoteProcedureDispatcher.RemoteOperation;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.hbase.shaded.protobuf.ProtobufUtil;
import org.apache.hadoop.hbase.shaded.protobuf.generated.MasterProcedureProtos.RemovePermissionRemoteStateData;

@InterfaceAudience.Private
public class RemovePermissionRemoteProcedure extends ServerRemoteProcedure
    implements ServerProcedureInterface {
  private static final Logger LOG = LoggerFactory.getLogger(RemovePermissionRemoteProcedure.class);
  private String entry;

  public RemovePermissionRemoteProcedure() {
  }

  public RemovePermissionRemoteProcedure(ServerName serverName, String entry) {
    this.targetServer = serverName;
    this.entry = entry;
  }

  @Override
  public ServerName getServerName() {
    return targetServer;
  }

  @Override
  public boolean hasMetaTableRegion() {
    return false;
  }

  @Override
  public ServerOperationType getServerOperationType() {
    return ServerOperationType.REFRESH_PERMISSION_CACHE;
  }

  @Override
  protected void complete(MasterProcedureEnv env, Throwable error) {
    if (error != null) {
      LOG.warn("Failed to remove permission entry {} on server {}", entry, targetServer, error);
      this.succ = false;
    } else {
      this.succ = true;
    }
  }

  @Override
  protected void rollback(MasterProcedureEnv env) throws IOException, InterruptedException {

  }

  @Override
  protected boolean abort(MasterProcedureEnv env) {
    return false;
  }

  @Override
  protected void serializeStateData(ProcedureStateSerializer serializer) throws IOException {
    RemovePermissionRemoteStateData.newBuilder()
        .setTargetServer(ProtobufUtil.toServerName(targetServer)).setEntry(entry).build();
  }

  @Override
  protected void deserializeStateData(ProcedureStateSerializer serializer) throws IOException {
    RemovePermissionRemoteStateData data =
        serializer.deserialize(RemovePermissionRemoteStateData.class);
    targetServer = ProtobufUtil.toServerName(data.getTargetServer());
    entry = data.getEntry();
  }

  @Override
  public RemoteOperation remoteCallBuild(MasterProcedureEnv env, ServerName remote) {
    assert targetServer.equals(remote);
    return new RSProcedureDispatcher.ServerOperation(this, getProcId(),
        RemovePermissionRemoteCallable.class,
        RemovePermissionRemoteStateData.newBuilder()
            .setTargetServer(ProtobufUtil.toServerName(remote)).setEntry(entry).build()
            .toByteArray());
  }

  @Override
  protected void toStringClassDetails(StringBuilder sb) {
    sb.append(getClass().getSimpleName());
    sb.append(" server=").append(targetServer);
    sb.append(", entry=").append(entry);
  }
}
