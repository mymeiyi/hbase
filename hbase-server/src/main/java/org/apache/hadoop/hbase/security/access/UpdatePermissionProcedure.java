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
import org.apache.hadoop.hbase.client.Table;
import org.apache.hadoop.hbase.master.procedure.MasterProcedureEnv;
import org.apache.hadoop.hbase.master.procedure.ProcedurePrepareLatch;
import org.apache.hadoop.hbase.master.procedure.ServerProcedureInterface;
import org.apache.hadoop.hbase.procedure2.ProcedureSuspendedException;
import org.apache.hadoop.hbase.procedure2.ProcedureUtil;
import org.apache.hadoop.hbase.procedure2.ProcedureYieldException;
import org.apache.hadoop.hbase.procedure2.StateMachineProcedure;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.hbase.util.RetryCounter;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hbase.thirdparty.com.google.common.collect.ListMultimap;
import org.apache.hadoop.hbase.shaded.protobuf.generated.MasterProcedureProtos.UpdatePermissionState;
import org.apache.hadoop.hbase.shaded.protobuf.generated.ProcedureProtos;

@InterfaceAudience.Private
public class UpdatePermissionProcedure
    extends StateMachineProcedure<MasterProcedureEnv, UpdatePermissionState>
    implements ServerProcedureInterface {
  private static Logger LOG = LoggerFactory.getLogger(UpdatePermissionProcedure.class);
  private UserPermission userPermission;
  private boolean mergeExistingPermissions;
  private boolean isGrant;
  private ServerName serverName;
  private ZKPermissionStorage zkPermissionStorage;
  private String entry;
  private byte[] userPermissions;
  private ProcedurePrepareLatch syncLatch;
  private RetryCounter retryCounter;

  public UpdatePermissionProcedure() {
  }

  public UpdatePermissionProcedure(UserPermission userPermission, boolean mergeExistingPermissions,
      boolean isGrant, ServerName serverName, ZKPermissionStorage zkPermissionStorage,
      ProcedurePrepareLatch syncLatch) {
    this.userPermission = userPermission;
    this.mergeExistingPermissions = mergeExistingPermissions;
    this.isGrant = isGrant;
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
          // update permission in acl table and acl znode
          updatePermissionStorage(env);
          // update permission in master auth manager cache
          env.getMasterServices().getAccessChecker().getAuthManager().refresh(entry,
            userPermissions);
        } catch (IOException e) {
          if (retryCounter == null) {
            retryCounter = ProcedureUtil.createRetryCounter(env.getMasterConfiguration());
          }
          long backoff = retryCounter.getBackoffTimeAndIncrementAttempts();
          LOG.warn(
            "Failed to update user permission {}, type {}, merge existing permissions {},  "
                + "sleep {} secs and retry",
            userPermission, isGrant ? "grant" : "revoke", mergeExistingPermissions, backoff / 1000,
            e);
          setTimeout(Math.toIntExact(backoff));
          setState(ProcedureProtos.ProcedureState.WAITING_TIMEOUT);
          skipPersistence();
          throw new ProcedureSuspendedException();
        }
        setNextState(UpdatePermissionState.UPDATE_PERMISSION_CACHE_ON_RS);
        return Flow.HAS_MORE_STATE;
      case UPDATE_PERMISSION_CACHE_ON_RS:
        // update permission in RS auth manager cache
        UpdatePermissionRemoteProcedure[] subProcedures =
            env.getMasterServices().getServerManager().getOnlineServersList().stream()
                .map(sn -> new UpdatePermissionRemoteProcedure(sn, entry, userPermissions))
                .toArray(UpdatePermissionRemoteProcedure[]::new);
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

  private void updatePermissionStorage(MasterProcedureEnv env) throws IOException {
    try (Table table =
        env.getMasterServices().getConnection().getTable(PermissionStorage.ACL_TABLE_NAME)) {
      // update permission to acl table
      if (isGrant) {
        PermissionStorage.addUserPermission(env.getMasterConfiguration(), userPermission, table,
          mergeExistingPermissions);
      } else {
        PermissionStorage.removeUserPermission(env.getMasterConfiguration(), userPermission, table);
      }
      // get updated permissions from acl table
      byte[] entryBytes = PermissionStorage.userPermissionRowKey(userPermission.getPermission());
      entry = Bytes.toString(entryBytes);
      ListMultimap<String, UserPermission> permissions = PermissionStorage
          .getPermissions(env.getMasterConfiguration(), entryBytes, table, null, null, null, false);
      userPermissions =
          PermissionStorage.writePermissionsAsBytes(permissions, env.getMasterConfiguration());
      // update permission to acl znode
      zkPermissionStorage.writePermission(entryBytes, userPermissions);
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
    sb.append(", user permission=").append(userPermission);
    sb.append(", mergeExistingPermissions=").append(mergeExistingPermissions);
    sb.append(", isGrant=").append(isGrant);
  }
}
