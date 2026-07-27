// AOSP android11-release IPackageManager:
// getPackagesForUid is transaction FIRST_CALL_TRANSACTION + 18.
package android.content.pm;

interface IPackageManager {
    String[] getPackagesForUid(int uid) = 18;
}
