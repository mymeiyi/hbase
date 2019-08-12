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
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.TableNotFoundException;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.client.ConnectionFactory;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hbase.thirdparty.com.google.common.collect.ListMultimap;

/**
 * Tool to sync HBase acls to hfiles
 */
@InterfaceAudience.Private
public class PresetHDFSAclTool {
  private static final Logger LOG = LoggerFactory.getLogger(PresetHDFSAclTool.class);
  /*
   * HDFS support 32 acls(16 users if a user own an access acl and a default acl). And there are 4
   * fixed users: owner, group, other and mask, so most support 12 named users.
   */
  private static final int TABLE_USER_NUM_THRESHOLD = 12;
  private static final int TABLE_USER_NUM_WARN_THRESHOLD = 9;
  /*
   * NAMESPACE_USER_NUM_THRESHOLD is a soft limitation, if a namespace has users with read
   * permission more than the limit, will log a warn info
   */
  private static final int NAMESPACE_USER_NUM_THRESHOLD = 5;
  private static final String PRESET_INCLUDE_PARAM = "include";

  private Configuration conf;
  private SnapshotScannerHDFSAclHelper hdfsAclHelper;
  private Connection connection;

  public PresetHDFSAclTool(Configuration conf) {
    this.conf = conf;
  }

  private void init() throws Exception {
    if (conf == null) {
      conf = HBaseConfiguration.create();
    }
    if (!SnapshotScannerHDFSAclHelper.isAclSyncToHdfsEnabled(conf)) {
      throw new UnsupportedOperationException("Snapshot HDFS Acl feature is not enabled");
    }
    connection = ConnectionFactory.createConnection(conf);
    hdfsAclHelper = new SnapshotScannerHDFSAclHelper(conf, connection);
  }

  private void cleanup() throws IOException {
    if (hdfsAclHelper != null) {
      hdfsAclHelper.close();
    }
    if (connection != null) {
      connection.close();
    }
  }

  private void presetHDFSAclInternal(String[] args) throws IOException {
    if (args != null && args.length >= 2) {
      String option = args[1];
      if (option != null && option.equals(PRESET_INCLUDE_PARAM)) {
        Set<TableName> tableSet = new HashSet<>();
        for (int i = 2; i < args.length; i++) {
          tableSet.add(TableName.valueOf(args[i]));
        }
        presetIncludeHDFSAcl(tableSet);
      } else {
        printUsage();
        return;
      }
    } else {
      presetAllHDFSAcl();
    }
  }

  private void presetIncludeHDFSAcl(Set<TableName> tables) throws IOException {
    for (TableName table : tables) {
      // TODO global and namespace
      Set<String> users = hdfsAclHelper.getUsersWithTableReadAction(table, false, false);
      hdfsAclHelper.grant(connection, table.getName(), users);
    }
  }

  private void presetAllHDFSAcl() throws IOException {
    Map<byte[], ListMultimap<String, UserPermission>> listMultimapMap =
        PermissionStorage.loadAll(conf);
    for (Map.Entry<byte[], ListMultimap<String, UserPermission>> entry : listMultimapMap
        .entrySet()) {
      byte[] key = entry.getKey();
      Set<String> users = hdfsAclHelper.getUsersWithReadAction(entry.getValue());
      hdfsAclHelper.grant(connection, key, users);
    }
  }

  private Map<String, Integer> checkHDFSAclEntryExceededInternal() throws IOException {
    final Set<String> globalUserSet = new HashSet<>();
    Map<String, Set<String>> nsUserMap = new HashMap<>();
    Map<TableName, Set<String>> tableUserMap = new HashMap<>();

    Map<byte[], ListMultimap<String, UserPermission>> listMultimapMap =
        PermissionStorage.loadAll(conf);
    for (Map.Entry<byte[], ListMultimap<String, UserPermission>> entry : listMultimapMap
        .entrySet()) {
      byte[] key = entry.getKey();
      Set<String> users = hdfsAclHelper.getUsersWithReadAction(entry.getValue());
      if (PermissionStorage.isNamespaceEntry(key)) {
        String namespace = Bytes.toString(PermissionStorage.fromNamespaceEntry(key));
        nsUserMap.put(namespace, users);
      } else if (PermissionStorage.isGlobalEntry(key)) {
        globalUserSet.addAll(users);
      } else {
        TableName tableName = TableName.valueOf(key);
        tableUserMap.put(tableName, users);
      }
    }

    LOG.debug("Found {} users with global read permission.", globalUserSet.size());
    nsUserMap.entrySet().forEach(en -> {
      en.getValue().addAll(globalUserSet);
      if (en.getValue().size() > NAMESPACE_USER_NUM_THRESHOLD) {
        LOG.warn("Found {} users with namespace '{}' read permission.", en.getValue().size(),
          en.getKey());
      } else {
        LOG.debug("Found {} users with namespace '{}' read permission.", en.getValue().size(),
          en.getKey());
      }
    });
    tableUserMap.entrySet().forEach(e -> {
      String ns = e.getKey().getNamespaceAsString();
      e.getValue().addAll(nsUserMap.getOrDefault(ns, new HashSet<>(0)));
      e.getValue().addAll(globalUserSet);
      if (e.getValue().size() > TABLE_USER_NUM_THRESHOLD) {
        LOG.error("Found {} users with table '{}' read permission.", e.getValue().size(),
          e.getKey().getNameAsString());
      } else if (e.getValue().size() > TABLE_USER_NUM_WARN_THRESHOLD) {
        LOG.warn("Found {} users with table '{}' read permission.", e.getValue().size(),
          e.getKey().getNameAsString());
      } else {
        LOG.debug("Found {} users with table '{}' read permission.", e.getValue().size(),
          e.getKey().getNameAsString());
      }
    });

    // return value used by test
    Map<String, Integer> entryUserNumMap = new HashMap<>();
    entryUserNumMap.put(PermissionStorage.ACL_TABLE_NAME.getNameAsString(), globalUserSet.size());
    nsUserMap.entrySet().forEach(e -> entryUserNumMap.put(e.getKey(), e.getValue().size()));
    tableUserMap.entrySet()
        .forEach(e -> entryUserNumMap.put(e.getKey().getNameAsString(), e.getValue().size()));
    return entryUserNumMap;
  }

  public Map<String, Integer> checkHDFSAclEntryExceeded() {
    try {
      init();
      Map<String, Integer> result = checkHDFSAclEntryExceededInternal();
      LOG.info("Finished check if HDFS ACLs entry exceeded.");
      return result;
    } catch (Exception e) {
      LOG.error("Failed check if HDFS ACLs entry exceeds", e);
    } finally {
      try {
        cleanup();
      } catch (IOException e) {
        LOG.error("Failed to close connection", e);
      }
    }
    return null;
  }

  public void presetHDFSAcl(String[] args) {
    try {
      init();
      hdfsAclHelper.setCommonDirectoryPermission();
      if (SnapshotScannerHDFSAclController.SnapshotScannerHDFSAclStorage
          .checkAclTable(connection.getAdmin())) {
        presetHDFSAclInternal(args);
        LOG.info("Finished to pre-set HDFS ACLs.");
      } else {
        throw new TableNotFoundException("Table " + PermissionStorage.ACL_TABLE_NAME
            + " is not created yet. Please check if " + getClass().getName()
            + " is configured after " + AccessController.class.getName());
      }
    } catch (Exception e) {
      LOG.error("Failed to preset HDFS ACLs", e);
    } finally {
      try {
        cleanup();
      } catch (IOException e) {
        LOG.error("Failed to close connection", e);
      }
    }
  }

  private static void printUsage() {
    StringWriter sw = new StringWriter(2048);
    PrintWriter out = new PrintWriter(sw);
    out.println("-----------------------------------------------------------------------");
    out.println("Usage: PresetHdfsAclTool [opts] {only tables}");
    out.println(" where [opts] are:");
    out.println("   checkHDFSAclExceeded: Check tables which has more than 12 users");
    out.println(
      "   presetHDFSAcl: Preset HDFS acls for all granted hbase acls(global namespace and table)");
    out.println(
      "   presetHDFSAcl include [tableName ...]: Preset HDFS ACLs just for the specified tables");
    out.println("-----------------------------------------------------------------------");
    out.flush();
    System.err.println(sw.toString());
  }

  public static void main(String[] args) {
    Configuration conf = HBaseConfiguration.create();
    PresetHDFSAclTool tool = new PresetHDFSAclTool(conf);
    if (args.length >= 1 && args[0].equals("presetHDFSAcl")) {
      tool.presetHDFSAcl(args);
    } else if (args.length == 1 && args[0].equals("checkHDFSAclExceeded")) {
      tool.checkHDFSAclEntryExceeded();
    } else {
      printUsage();
      System.exit(1);
    }
  }
}
