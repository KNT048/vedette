package core

// EncryptBackupForTest is encryptBackup for the tests of package core_test.
var EncryptBackupForTest = encryptBackup

// The tests encrypt at a cheap scrypt cost (2^10, 1 MiB): the cost is age's, and a full one would add a second per download.
func init() { backupWorkFactor = 10 }
