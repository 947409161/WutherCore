// AOSP android12-release through android16-release IPackageManager:
// getPackagesForUid is transaction FIRST_CALL_TRANSACTION + 19.
package android.content.pm;

interface IPackageManager {
    String[] getPackagesForUid(int uid) = 19;
}
