/*
 * WinStaDesktopAcl
 * ----------------
 * Windows services run in Session 0, which owns a special window station ("winsta0")
 * and desktop ("default"). When a service launches a process under alternate
 * credentials (for example, an impersonated user via CreateProcessWithLogonW),
 * that user does not, by default, have permission to access Session 0’s
 * window station and desktop objects.
 *
 * During process startup, user32.dll attempts to open handles to these GUI
 * objects—even for console or background programs. If access is denied,
 * process initialization fails immediately with errors such as:
 *
 *   - ExitCode = 0xC0000142 (STATUS_DLL_INIT_FAILED)
 *   - "The parameter is incorrect" from CreateProcessWithLogonW
 *
 * The WinStaDesktopAcl class resolves this by temporarily granting the target
 * user account full access (WINDOW_STATION_ALL_ACCESS and DESKTOP_ALL_ACCESS)
 * to the current process’s window station and desktop security descriptors.
 *
 * This fix allows impersonated processes (e.g., pwsh.exe started from a service)
 * to initialize correctly within Session 0, without requiring permanent ACL
 * changes or interactive logon rights.
 *
 * In short:
 *   WinStaDesktopAcl.GrantTo("DOMAIN\\User");
 * ensures the impersonated user can start GUI-initializing processes safely
 * from a Windows service context.
 * https://stackoverflow.com/questions/677874/starting-a-process-with-credentials-from-a-windows-service
 */

using System;
using System.Runtime.InteropServices;
using System.Text;

internal static class WinStaDesktopAcl
{
    // ---------------- P/Invoke ----------------
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr GetThreadDesktop(uint dwThreadId);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetSecurityInfo(
        IntPtr handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo,
        out IntPtr ppsidOwner, out IntPtr ppsidGroup, out IntPtr ppDacl, out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint SetSecurityInfo(
        IntPtr handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo,
        IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint SetEntriesInAclW(
        int cCountOfExplicitEntries, [In] ref EXPLICIT_ACCESS_W pListOfExplicitEntries,
        IntPtr OldAcl, out IntPtr NewAcl);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupAccountNameW(
        string lpSystemName,
        string lpAccountName,
        IntPtr Sid,
        ref uint cbSid,
        StringBuilder ReferencedDomainName,
        ref uint cchReferencedDomainName,
        out SID_NAME_USE peUse);

    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr hMem);

    // ---------------- Types/enums ----------------
    [Flags]
    private enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION = 0x00000001,
        GROUP_SECURITY_INFORMATION = 0x00000002,
        DACL_SECURITY_INFORMATION = 0x00000004,
        SACL_SECURITY_INFORMATION = 0x00000008
    }

    private enum SE_OBJECT_TYPE
    {
        SE_UNKNOWN_OBJECT_TYPE = 0,
        SE_FILE_OBJECT,
        SE_SERVICE,
        SE_PRINTER,
        SE_REGISTRY_KEY,
        SE_LMSHARE,
        SE_KERNEL_OBJECT,
        SE_WINDOW_OBJECT, // <--- window station / desktop
        SE_DS_OBJECT,
        SE_DS_OBJECT_ALL,
        SE_PROVIDER_DEFINED_OBJECT,
        SE_WMIGUID_OBJECT,
        SE_REGISTRY_WOW64_32KEY
    }

    private enum SID_NAME_USE
    {
        SidTypeUser = 1, SidTypeGroup, SidTypeDomain, SidTypeAlias, SidTypeWellKnownGroup,
        SidTypeDeletedAccount, SidTypeInvalid, SidTypeUnknown, SidTypeComputer, SidTypeLabel
    }

    private enum TRUSTEE_FORM { TRUSTEE_IS_SID = 0, TRUSTEE_IS_NAME = 1 }
    private enum TRUSTEE_TYPE { TRUSTEE_IS_UNKNOWN = 0, TRUSTEE_IS_USER = 1, TRUSTEE_IS_GROUP = 2 }
    private enum ACCESS_MODE { NOT_USED_ACCESS = 0, GRANT_ACCESS, SET_ACCESS, DENY_ACCESS, REVOKE_ACCESS, SET_AUDIT_SUCCESS, SET_AUDIT_FAILURE }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TRUSTEE_W
    {
        public IntPtr pMultipleTrustee;
        public int MultipleTrusteeOperation;
        public TRUSTEE_FORM TrusteeForm;
        public TRUSTEE_TYPE TrusteeType;
        public IntPtr ptstrName; // LPWSTR (name or SID ptr)
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EXPLICIT_ACCESS_W
    {
        public uint grfAccessPermissions;
        public ACCESS_MODE grfAccessMode;
        public uint grfInheritance;
        public TRUSTEE_W Trustee;
    }

    // Access masks (include GENERIC bits)
    private const uint WINDOW_STATION_ALL_ACCESS = 0x000F037F;
    private const uint DESKTOP_ALL_ACCESS = 0x000F01FF;

    private const uint NO_INHERITANCE = 0x0;

    // ---------------- Public API ----------------
    /// <summary>
    /// Grants full access on Session 0 window station ("winsta0") and current thread desktop ("default")
    /// to the specified account name (e.g. "MACHINE\\User" or "DOMAIN\\User").
    /// </summary>
    public static void GrantTo(string accountName)
    {
        if (string.IsNullOrWhiteSpace(accountName))
            throw new ArgumentNullException(nameof(accountName));

        // Resolve to SID
        IntPtr pSid = IntPtr.Zero;
        try
        {
            pSid = LookupSidForAccount(accountName);

            // Handles for current process/window objects
            IntPtr hWinSta = GetProcessWindowStation();
            if (hWinSta == IntPtr.Zero) throw new InvalidOperationException("GetProcessWindowStation failed.");

            IntPtr hDesk = GetThreadDesktop(GetCurrentThreadId());
            if (hDesk == IntPtr.Zero) throw new InvalidOperationException("GetThreadDesktop failed.");

            AddAllowAce(hWinSta, SE_OBJECT_TYPE.SE_WINDOW_OBJECT, pSid, WINDOW_STATION_ALL_ACCESS);
            AddAllowAce(hDesk, SE_OBJECT_TYPE.SE_WINDOW_OBJECT, pSid, DESKTOP_ALL_ACCESS);
        }
        finally
        {
            if (pSid != IntPtr.Zero) Marshal.FreeHGlobal(pSid);
        }
    }

    // ---------------- Internals ----------------
    private static void AddAllowAce(IntPtr handle, SE_OBJECT_TYPE objType, IntPtr pSid, uint accessMask)
    {
        // Get existing DACL
        IntPtr pOldDacl, pSD, pOwner, pGroup, pSacl;
        uint err = GetSecurityInfo(handle, objType, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                                   out pOwner, out pGroup, out pOldDacl, out pSacl, out pSD);
        if (err != 0) throw new InvalidOperationException("GetSecurityInfo failed: " + err);

        // Build explicit access entry
        EXPLICIT_ACCESS_W ea = new EXPLICIT_ACCESS_W();
        ea.grfAccessPermissions = accessMask;
        ea.grfAccessMode = ACCESS_MODE.GRANT_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee = new TRUSTEE_W
        {
            pMultipleTrustee = IntPtr.Zero,
            MultipleTrusteeOperation = 0,
            TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID,
            TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_USER,
            ptstrName = pSid
        };

        // Merge new ACE
        IntPtr pNewAcl;
        err = SetEntriesInAclW(1, ref ea, pOldDacl, out pNewAcl);
        if (err != 0) throw new InvalidOperationException("SetEntriesInAclW failed: " + err);

        try
        {
            // Set new DACL
            err = SetSecurityInfo(handle, objType, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                                  IntPtr.Zero, IntPtr.Zero, pNewAcl, IntPtr.Zero);
            if (err != 0) throw new InvalidOperationException("SetSecurityInfo failed: " + err);
        }
        finally
        {
            if (pNewAcl != IntPtr.Zero) LocalFree(pNewAcl);
            if (pSD != IntPtr.Zero) LocalFree(pSD);
        }
    }

    private static IntPtr LookupSidForAccount(string accountName)
    {
        uint cbSid = 0, cchRefDom = 0;
        SID_NAME_USE use;
        // First call to get sizes
        bool ok = LookupAccountNameW(null, accountName, IntPtr.Zero, ref cbSid,
                                     null, ref cchRefDom, out use);
        int lastErr = Marshal.GetLastWin32Error();
        if (ok || lastErr != 122 /*ERROR_INSUFFICIENT_BUFFER*/)
            throw new InvalidOperationException("LookupAccountName(size) failed: " + lastErr);

        IntPtr pSid = Marshal.AllocHGlobal((int)cbSid);
        var refDom = new StringBuilder((int)cchRefDom);

        if (!LookupAccountNameW(null, accountName, pSid, ref cbSid, refDom, ref cchRefDom, out use))
        {
            lastErr = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(pSid);
            throw new InvalidOperationException("LookupAccountName(data) failed: " + lastErr);
        }
        return pSid;
    }
}
