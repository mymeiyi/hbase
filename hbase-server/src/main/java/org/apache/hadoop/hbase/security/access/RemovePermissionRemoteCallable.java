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

import org.apache.hadoop.hbase.executor.EventType;
import org.apache.hadoop.hbase.procedure2.RSProcedureCallable;
import org.apache.hadoop.hbase.regionserver.HRegionServer;
import org.apache.yetus.audience.InterfaceAudience;

import org.apache.hbase.thirdparty.com.google.protobuf.InvalidProtocolBufferException;
import org.apache.hadoop.hbase.shaded.protobuf.generated.MasterProcedureProtos.RemovePermissionStateData;

@InterfaceAudience.Private
public class RemovePermissionRemoteCallable implements RSProcedureCallable {
  private HRegionServer rs;
  private Exception initError;
  private String entry;

  public RemovePermissionRemoteCallable() {
  }

  @Override
  public void init(byte[] parameter, HRegionServer rs) {
    this.rs = rs;
    try {
      RemovePermissionStateData param = RemovePermissionStateData.parseFrom(parameter);
      entry = param.getEntry();
    } catch (InvalidProtocolBufferException e) {
      initError = e;
    }
  }

  @Override
  public EventType getEventType() {
    return EventType.M_RS_REFRESH_PERMISSION_CACHE;
  }

  @Override
  public Void call() throws Exception {
    if (initError != null) {
      throw initError;
    }
    rs.getAccessChecker().getAuthManager().remove(entry);
    return null;
  }
}
