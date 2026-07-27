// AOSP android-10.0.0_r1 IPackageManager:
// getPackagesForUid is transaction FIRST_CALL_TRANSACTION + 36.
package android.content.pm;

interface IPackageManager {
    String[] getPackagesForUid(int uid) = 36;
}
