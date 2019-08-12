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

import static org.apache.hadoop.hbase.security.access.Permission.Action.READ;
import static org.apache.hadoop.hbase.security.access.Permission.Action.WRITE;

import java.util.List;
import java.util.Map;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hbase.HBaseClassTestRule;
import org.apache.hadoop.hbase.HBaseTestingUtility;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.Admin;
import org.apache.hadoop.hbase.client.Table;
import org.apache.hadoop.hbase.coprocessor.CoprocessorHost;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.testclassification.MediumTests;
import org.apache.hadoop.hbase.testclassification.SecurityTests;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.TestName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Category({ SecurityTests.class, MediumTests.class })
public class TestPresetHDFSAclTool {
  @ClassRule
  public static final HBaseClassTestRule CLASS_RULE =
      HBaseClassTestRule.forClass(TestPresetHDFSAclTool.class);

  @Rule
  public TestName name = new TestName();
  private static final Logger LOG = LoggerFactory.getLogger(TestPresetHDFSAclTool.class);

  private static HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();
  private static Configuration conf = TEST_UTIL.getConfiguration();
  private static Admin admin = null;
  private static FileSystem fs = null;
  private static Path rootDir = null;
  private static SnapshotScannerHDFSAclHelper helper;

  @BeforeClass
  public static void setupBeforeClass() throws Exception {
    conf.setBoolean("dfs.namenode.acls.enabled", true);
    conf.set("fs.permissions.umask-mode", "027");
    conf.set(User.HBASE_SECURITY_CONF_KEY, "simple");
    SecureTestUtil.enableSecurity(conf);
    TEST_UTIL.startMiniCluster();
    admin = TEST_UTIL.getAdmin();
    rootDir = TEST_UTIL.getHBaseCluster().getMaster().getMasterFileSystem().getRootDir();
    fs = rootDir.getFileSystem(conf);
    helper = new SnapshotScannerHDFSAclHelper(conf, admin.getConnection());

    FsPermission commonPermission =
        new FsPermission(conf.get(SnapshotScannerHDFSAclHelper.COMMON_DIRECTORY_PERMISSION,
          SnapshotScannerHDFSAclHelper.COMMON_DIRECTORY_PERMISSION_DEFAULT));
    Path path = rootDir;
    while (path != null) {
      fs.setPermission(path, commonPermission);
      path = path.getParent();
    }

    FsPermission restorePermission = new FsPermission(
        conf.get(SnapshotScannerHDFSAclHelper.SNAPSHOT_RESTORE_DIRECTORY_PERMISSION,
          SnapshotScannerHDFSAclHelper.SNAPSHOT_RESTORE_DIRECTORY_PERMISSION_DEFAULT));
    Path restoreDir = new Path(SnapshotScannerHDFSAclHelper.SNAPSHOT_RESTORE_TMP_DIR_DEFAULT);
    if (!fs.exists(restoreDir)) {
      fs.mkdirs(restoreDir);
      fs.setPermission(restoreDir, restorePermission);
    }
    path = restoreDir.getParent();
    while (path != null) {
      fs.setPermission(path, commonPermission);
      path = path.getParent();
    }
    TEST_UTIL.waitTableAvailable(PermissionStorage.ACL_TABLE_NAME);
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    TEST_UTIL.shutdownMiniCluster();
  }

  @Test
  public void testPresetGlobalAcl() throws Exception {
    String grantUserName = name.getMethodName();
    User grantUser = User.createUserForTesting(conf, grantUserName, new String[] {});
    String namespace = name.getMethodName();
    TableName tableName = TableName.valueOf(namespace, "t1");
    String snapshot = namespace + "t1";
    try {
      TestHDFSAclHelper.createTableAndPut(TEST_UTIL, tableName);
      SecureTestUtil.grantGlobal(TEST_UTIL, grantUserName, READ);
      admin.snapshot(snapshot, tableName);
      TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot, -1);
      // run preset
      presetHDFSAcl();
      // check scan snapshot
      TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot, 6);
      // check global dirs exist
      List<Path> globalRootPaths = helper.getGlobalRootPaths();
      for (Path path : globalRootPaths) {
        TestHDFSAclHelper.checkUserAclEntry(fs, path, grantUserName, true, true);
      }
      // check permission is stored in acl table
      try (Table aclTable = admin.getConnection().getTable(PermissionStorage.ACL_TABLE_NAME)) {
        SnapshotScannerHDFSAclController.SnapshotScannerHDFSAclStorage
            .hasUserGlobalHdfsAcl(aclTable, grantUserName);
      }
    } finally {
      SecureTestUtil.revokeGlobal(TEST_UTIL, grantUserName, READ);
    }
  }

  @Test
  public void testPresetNamespaceAcl() throws Exception {
    String grantUserName = name.getMethodName();
    User grantUser = User.createUserForTesting(conf, grantUserName, new String[] {});
    String namespace = name.getMethodName();
    TableName tableName = TableName.valueOf(namespace, "t1");
    String snapshot = namespace + "t1";
    TableName tableName2 = TableName.valueOf(namespace, "t2");
    String snapshot2 = namespace + "t2";
    // create table1 with acl enabled
    TestHDFSAclHelper.createTableAndPut(TEST_UTIL, tableName);
    admin.snapshot(snapshot, tableName);
    // create table2 with acl disabled
    TestHDFSAclHelper.createUserScanSnapshotDisabledTable(TEST_UTIL, tableName2);
    admin.snapshot(snapshot2, tableName2);
    // grant on namespace
    SecureTestUtil.grantOnNamespace(TEST_UTIL, grantUserName, namespace, READ);
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot, -1);
    // run preset
    presetHDFSAcl();
    // check scan snapshot
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot, 6);
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot2, -1);
    // check namespace dirs exist
    List<Path> namespaceRootPaths = helper.getNamespaceRootPaths(namespace);
    for (Path path : namespaceRootPaths) {
      TestHDFSAclHelper.checkUserAclEntry(fs, path, grantUserName, true, true);
    }
    // check permission is stored in acl table
    try (Table aclTable = admin.getConnection().getTable(PermissionStorage.ACL_TABLE_NAME)) {
      SnapshotScannerHDFSAclController.SnapshotScannerHDFSAclStorage
          .hasUserNamespaceHdfsAcl(aclTable, grantUserName, namespace);
    }
  }

  @Test
  public void testPresetTableAcl() throws Exception {
    String grantUserName = name.getMethodName();
    User grantUser = User.createUserForTesting(conf, grantUserName, new String[] {});
    String namespace = name.getMethodName();
    TableName tableName = TableName.valueOf(namespace, "t1");
    String snapshot = namespace + "t1";
    String snapshot2 = namespace + "t2";

    TestHDFSAclHelper.createUserScanSnapshotDisabledTable(TEST_UTIL, tableName);
    admin.snapshot(snapshot, tableName);
    admin.snapshot(snapshot2, tableName);

    TestHDFSAclHelper.grantOnTable(TEST_UTIL, grantUserName, tableName, WRITE);
    presetHDFSAcl();
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot, -1);
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot2, -1);

    SecureTestUtil.grantOnTable(TEST_UTIL, grantUserName, tableName, TestHDFSAclHelper.COLUMN1,
      null, READ);
    presetHDFSAcl();
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot, -1);
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot2, -1);

    TestHDFSAclHelper.grantOnTable(TEST_UTIL, grantUserName, tableName, READ);
    presetHDFSAcl();
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot, 6);
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot2, 6);
    // check namespace dirs exist
    List<Path> tableRootPaths = helper.getTableRootPaths(tableName, true);
    for (Path path : tableRootPaths) {
      TestHDFSAclHelper.checkUserAclEntry(fs, path, grantUserName, true, true);
    }
    // check permission is stored in acl table
    try (Table aclTable = admin.getConnection().getTable(PermissionStorage.ACL_TABLE_NAME)) {
      SnapshotScannerHDFSAclController.SnapshotScannerHDFSAclStorage.hasUserTableHdfsAcl(aclTable,
        grantUserName, tableName);
    }
  }

  @Test
  public void testPresetHDFSAclWithInclude() throws Exception {
    String grantUserName = name.getMethodName();
    User grantUser = User.createUserForTesting(conf, grantUserName, new String[] {});
    String namespace = name.getMethodName();
    TableName tableName1 = TableName.valueOf(namespace, "t1");
    TableName tableName2 = TableName.valueOf(namespace, "t2");
    String snapshot1 = namespace + "t1";
    String snapshot2 = namespace + "t2";

    TestHDFSAclHelper.createTableAndPut(TEST_UTIL, tableName1);
    TestHDFSAclHelper.createTable(TEST_UTIL, tableName2);
    TestHDFSAclHelper.grantOnTable(TEST_UTIL, grantUserName, tableName1, READ);
    TestHDFSAclHelper.grantOnTable(TEST_UTIL, grantUserName, tableName2, READ);
    admin.snapshot(snapshot1, tableName1);
    admin.snapshot(snapshot2, tableName2);
    enableConf();
    PresetHDFSAclTool tool = new PresetHDFSAclTool(conf);
    tool.presetHDFSAcl(new String[] { "", "include", tableName1.getNameAsString() });

    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot1, 6);
    TestHDFSAclHelper.canUserScanSnapshot(TEST_UTIL, grantUser, snapshot2, -1);
  }

  @Test
  public void testCheckHDFSAclExceeded() throws Exception {
    String methodName = name.getMethodName();
    String ns1 = methodName + "1";
    String ns2 = methodName + "2";
    TableName ns1T2 = TableName.valueOf(ns1, "t1");
    TableName ns2T1 = TableName.valueOf(ns2, "t1");

    String globalUser = "g-u1";
    String ns2User1 = "ns2-u1";
    String ns2User2 = "ns2-u2";
    String ns1T2User1 = "ns1-t2-u1";
    String ns2T1User1 = "ns2-t1-u1";
    String ns2T1User2 = "ns2-t1-u2";
    String ns2T1User3 = "ns2-t1-u3";

    SecureTestUtil.grantGlobal(TEST_UTIL, globalUser, READ);
    // grant to ns2
    SecureTestUtil.grantOnNamespace(TEST_UTIL, ns2User1, ns2, READ);
    SecureTestUtil.grantOnNamespace(TEST_UTIL, ns2User2, ns2, READ);
    // grant to ns1:t2
    TestHDFSAclHelper.grantOnTable(TEST_UTIL, ns1T2User1, ns1T2, READ);
    // grant to ns2:t1
    TestHDFSAclHelper.grantOnTable(TEST_UTIL, ns2User1, ns2T1, READ);
    TestHDFSAclHelper.grantOnTable(TEST_UTIL, ns2T1User1, ns2T1, READ);
    TestHDFSAclHelper.grantOnTable(TEST_UTIL, ns2T1User2, ns2T1, WRITE);
    SecureTestUtil.grantOnTable(TEST_UTIL, ns2T1User3, ns2T1, Bytes.toBytes("A"), null, WRITE);

    enableConf();
    PresetHDFSAclTool tool = new PresetHDFSAclTool(conf);
    Map<String, Integer> entryUserNumMap = tool.checkHDFSAclEntryExceeded();
    Assert.assertTrue(
      entryUserNumMap.get(PermissionStorage.ACL_TABLE_NAME.getNameAsString()).intValue() >= 1);
    Assert.assertTrue(entryUserNumMap.get(ns2).intValue() >= 3);
    Assert.assertTrue(entryUserNumMap.get(ns1T2.getNameAsString()).intValue() >= 2);
    Assert.assertTrue(entryUserNumMap.get(ns2T1.getNameAsString()).intValue() >= 4);
  }

  private void enableConf() {
    conf.set(CoprocessorHost.MASTER_COPROCESSOR_CONF_KEY,
      conf.get(CoprocessorHost.MASTER_COPROCESSOR_CONF_KEY) + ","
          + SnapshotScannerHDFSAclController.class.getName());
    conf.setBoolean(SnapshotScannerHDFSAclHelper.ACL_SYNC_TO_HDFS_ENABLE, true);
  }

  private void presetHDFSAcl() {
    enableConf();
    PresetHDFSAclTool tool = new PresetHDFSAclTool(conf);
    tool.presetHDFSAcl(null);
  }
}
