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
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.Table;
import org.apache.hadoop.hbase.master.procedure.MasterProcedureEnv;
import org.apache.hadoop.hbase.master.procedure.ProcedurePrepareLatch;
import org.apache.hadoop.hbase.master.procedure.ServerProcedureInterface;
import org.apache.hadoop.hbase.procedure2.ProcedureSuspendedException;
import org.apache.hadoop.hbase.procedure2.ProcedureUtil;
import org.apache.hadoop.hbase.procedure2.ProcedureYieldException;
import org.apache.hadoop.hbase.procedure2.StateMachineProcedure;
import org.apache.hadoop.hbase.util.RetryCounter;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.hbase.shaded.protobuf.generated.MasterProcedureProtos.UpdatePermissionState;
import org.apache.hadoop.hbase.shaded.protobuf.generated.ProcedureProtos;

@InterfaceAudience.Private
public class RemovePermissionProcedure
    extends StateMachineProcedure<MasterProcedureEnv, UpdatePermissionState>
    implements ServerProcedureInterface {
  private static Logger LOG = LoggerFactory.getLogger(RemovePermissionProcedure.class);
  private String entry;
  private ServerName serverName;
  private ZKPermissionStorage zkPermissionStorage;
  private ProcedurePrepareLatch syncLatch;
  private RetryCounter retryCounter;

  public RemovePermissionProcedure() {
  }

  public RemovePermissionProcedure(String entry, ServerName serverName,
      ZKPermissionStorage zkPermissionStorage, ProcedurePrepareLatch syncLatch) {
    this.entry = entry;
    this.serverName = serverName;
    this.zkPermissionStorage = zkPermissionStorage;
    this.syncLatch = syncLatch;
  }

  @Override
  public ServerName getServerName() {
    return serverName;
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
  protected Flow executeFromState(MasterProcedureEnv env, UpdatePermissionState state)
      throws ProcedureSuspendedException, ProcedureYieldException, InterruptedException {
    switch (state) {
      case UPDATE_PERMISSION_STORAGE:
        try {
          // remove permission to acl table and acl znode
          removePermissionFromStorage(env);
          // remove permission from master auth manager cache
          env.getMasterServices().getAccessChecker().getAuthManager().remove(entry);
        } catch (IOException e) {
          if (retryCounter == null) {
            retryCounter = ProcedureUtil.createRetryCounter(env.getMasterConfiguration());
          }
          long backoff = retryCounter.getBackoffTimeAndIncrementAttempts();
          LOG.warn("Failed to remove permission for entry {}, sleep {} secs and retry", entry,
            backoff / 1000, e);
          setTimeout(Math.toIntExact(backoff));
          setState(ProcedureProtos.ProcedureState.WAITING_TIMEOUT);
          skipPersistence();
          throw new ProcedureSuspendedException();
        }
        setNextState(UpdatePermissionState.UPDATE_PERMISSION_CACHE_ON_RS);
        return Flow.HAS_MORE_STATE;
      case UPDATE_PERMISSION_CACHE_ON_RS:
        // remove permission from RS auth manager cache
        RemovePermissionRemoteProcedure[] subProcedures =
            env.getMasterServices().getServerManager().getOnlineServersList().stream()
                .map(sn -> new RemovePermissionRemoteProcedure(sn, entry))
                .toArray(RemovePermissionRemoteProcedure[]::new);
        addChildProcedure(subProcedures);
        setNextState(UpdatePermissionState.POST_UPDATE_PERMISSION);
        return Flow.HAS_MORE_STATE;
      case POST_UPDATE_PERMISSION:
        ProcedurePrepareLatch.releaseLatch(syncLatch, this);
        return Flow.NO_MORE_STATE;
      default:
        throw new UnsupportedOperationException("unhandled state=" + state);
    }
  }

  private void removePermissionFromStorage(MasterProcedureEnv env) throws IOException {
    try (Table table =
        env.getMasterServices().getConnection().getTable(PermissionStorage.ACL_TABLE_NAME)) {
      if (PermissionStorage.isNamespaceEntry(entry)) {
        String namespace = PermissionStorage.fromNamespaceEntry(entry);
        PermissionStorage.removeNamespacePermissions(env.getMasterConfiguration(), namespace,
          table);
        zkPermissionStorage.deleteNamespacePermission(namespace);
      } else {
        TableName tableName = TableName.valueOf(entry);
        PermissionStorage.removeTablePermissions(env.getMasterConfiguration(), tableName, table);
        zkPermissionStorage.deleteTablePermission(tableName);
      }
    }
  }

  @Override
  protected void rollbackState(MasterProcedureEnv env, UpdatePermissionState accessControlState)
      throws IOException, InterruptedException {
  }

  @Override
  protected UpdatePermissionState getState(int stateId) {
    return UpdatePermissionState.forNumber(stateId);
  }

  @Override
  protected int getStateId(UpdatePermissionState accessControlState) {
    return accessControlState.getNumber();
  }

  @Override
  protected UpdatePermissionState getInitialState() {
    return UpdatePermissionState.UPDATE_PERMISSION_STORAGE;
  }

  @Override
  protected void toStringClassDetails(StringBuilder sb) {
    sb.append(getClass().getSimpleName());
    sb.append(" server=").append(serverName);
    sb.append(", entry=").append(entry);
  }
}
