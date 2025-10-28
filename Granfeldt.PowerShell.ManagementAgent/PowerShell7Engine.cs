using System;
using System.Collections;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Threading.Tasks;
using System.Runtime.Serialization.Json;

namespace Granfeldt
{
    /// <summary>
    /// Exception thrown when PowerShell 7 impersonation fails and automatic fallback to Windows PowerShell is recommended
    /// </summary>
    public class PowerShell7ImpersonationException : Exception
    {
        public bool ShouldFallbackToWindowsPowerShell { get; }
        
        public PowerShell7ImpersonationException(string message, bool shouldFallback = true) 
            : base(message)
        {
            ShouldFallbackToWindowsPowerShell = shouldFallback;
        }
        
        public PowerShell7ImpersonationException(string message, Exception innerException, bool shouldFallback = true) 
            : base(message, innerException)
        {
            ShouldFallbackToWindowsPowerShell = shouldFallback;
        }
    }
    /// <summary>
    /// PowerShell engine implementation for PowerShell 7+ with true out-of-process execution
    /// This engine launches PowerShell 7+ as a separate process to execute scripts with full PS7 feature support
    /// </summary>
    public class PowerShell7Engine : IPowerShellEngine
    {
        private bool disposed = false;
        private readonly string powerShell7ExecutablePath;
        private Dictionary<string, object> sessionVariables = new Dictionary<string, object>();

        public Version PowerShellVersion => new Version(7, 0);
        public string EngineType => "PowerShell 7+ (Out-of-Process)";
        public bool IsInitialized => !string.IsNullOrEmpty(powerShell7ExecutablePath) && File.Exists(powerShell7ExecutablePath);

        public event EventHandler<DataAddedEventArgs> PowerShellError;
        public event EventHandler<DataAddedEventArgs> PowerShellVerbose;
        public event EventHandler<DataAddedEventArgs> PowerShellWarning;
        public event EventHandler<DataAddedEventArgs> PowerShellDebug;
        public event EventHandler<DataAddedEventArgs> PowerShellProgress;

        public PowerShell7Engine(string executablePath)
        {
            powerShell7ExecutablePath = executablePath ?? @"C:\Program Files\PowerShell\7\pwsh.exe";
            Tracer.TraceInformation("*** INITIALIZING TRUE OUT-OF-PROCESS POWERSHELL 7+ ENGINE ***");
            Tracer.TraceInformation("powershell7-executable-path: {0}", powerShell7ExecutablePath);
        }

        // Impersonation support for out-of-process execution
        public void SetImpersonationCredentials(string username, string domain, string password)
        {
            // Log what credentials are being set (for debugging UI persistence issues)
            Tracer.TraceInformation("powershell7-setimpersonationcredentials domain: '{0}', username: '{1}', password-length: {2}", 
                domain ?? "<empty>", 
                username ?? "<empty>", 
                string.IsNullOrEmpty(password) ? 0 : password.Length);
            
            SetVariable("_ImpersonationUsername", username);
            SetVariable("_ImpersonationDomain", domain);
            SetVariable("_ImpersonationPassword", password);
            
            // Check for partial credential configuration (common with UI persistence bugs)
            bool hasUsername = !string.IsNullOrEmpty(username);
            bool hasPassword = !string.IsNullOrEmpty(password);
            
            if (hasUsername && hasPassword)
            {
                // Both provided - validate credentials
                try
                {
                    Tracer.TraceInformation("validating-impersonation-credentials-for-powershell7 domain: '{0}', username: '{1}'", domain ?? "", username);
                    ValidateImpersonationCredentials(username, domain, password);
                    SetVariable("_ImpersonationRequested", true);
                    Tracer.TraceInformation("impersonation-credentials-validated-successfully-for-powershell7");
                }
                catch (Exception ex)
                {
                    Tracer.TraceError($"impersonation-credential-validation-failed-for-powershell7: {ex.Message}");
                    
                    // Determine if this is a credential issue or a platform limitation
                    // Fix: Properly detect Windows Server 2012 R2 (version 6.3) vs newer versions
                    Version osVersion = System.Environment.OSVersion.Version;
                    bool isServer2012R2 = osVersion.Major == 6 && osVersion.Minor == 3;
                    
                    Tracer.TraceInformation("os-version-detection major: {0}, minor: {1}, build: {2}, is-server2012r2: {3}", 
                        osVersion.Major, osVersion.Minor, osVersion.Build, isServer2012R2);
                    
                    string errorMessage = isServer2012R2 
                        ? $"PowerShell 7+ impersonation is not supported on Windows Server 2012 R2 due to platform limitations. Credential validation failed: {ex.Message}. Please use Windows PowerShell 5.1 for operations requiring impersonation, or configure PowerShell 7+ to run without impersonation (as the synchronization service account)."
                        : $"PowerShell 7+ impersonation credential validation failed: {ex.Message}. Please verify the domain, username, and password are correct.";
                        
                    throw new System.Security.SecurityException(errorMessage, ex);
                }
            }
            else if (hasUsername || hasPassword)
            {
                // Partial credentials provided - likely UI persistence bug
                Tracer.TraceWarning("powershell7-partial-impersonation-credentials-detected username-provided: '{0}', password-provided: '{1}'", 1, hasUsername ? "true" : "false", hasPassword ? "true" : "false");
                Tracer.TraceWarning("powershell7-ignoring-partial-credentials-running-without-impersonation");
                
                // Clear both to ensure no impersonation is attempted
                SetVariable("_ImpersonationUsername", null);
                SetVariable("_ImpersonationPassword", null);
                SetVariable("_ImpersonationRequested", false);
            }
            else
            {
                // No credentials provided - normal case
                Tracer.TraceInformation("powershell7-no-impersonation-credentials-provided-running-without-impersonation");
                SetVariable("_ImpersonationRequested", false);
            }
        }

        /// <summary>
        /// Validates impersonation credentials using Windows LogonUser API
        /// </summary>
        private void ValidateImpersonationCredentials(string username, string domain, string password)
        {
            IntPtr token = IntPtr.Zero;
            try
            {
                // Import LogonUser from advapi32.dll for credential validation
                const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
                const int LOGON32_PROVIDER_WINNT50 = 3;
                
                bool success = LogonUser(
                    username,
                    domain,
                    password,
                    LOGON32_LOGON_NETWORK_CLEARTEXT,
                    LOGON32_PROVIDER_WINNT50,
                    out token);
                
                if (!success)
                {
                    int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                    string errorMessage = GetLogonErrorMessage(error);
                    throw new System.Security.SecurityException($"Credential validation failed: {errorMessage} (Error code: {error})");
                }
                
                Tracer.TraceInformation("credential-validation-successful domain: '{0}', username: '{1}'", domain ?? "", username);
            }
            finally
            {
                if (token != IntPtr.Zero)
                {
                    CloseHandle(token);
                }
            }
        }

        /// <summary>
        /// Provides user-friendly error messages for common logon failures
        /// </summary>
        private string GetLogonErrorMessage(int errorCode)
        {
            switch (errorCode)
            {
                case 1326: // ERROR_LOGON_FAILURE
                    return "Invalid username or password";
                case 1327: // ERROR_INVALID_LOGON_HOURS
                    return "Account not permitted to logon at this time";
                case 1330: // ERROR_PASSWORD_EXPIRED
                    return "Password has expired";
                case 1331: // ERROR_ACCOUNT_RESTRICTION / ERROR_ACCOUNT_DISABLED
                    return "Account restrictions prevent logon (disabled, locked, or other restrictions)";
                case 1332: // ERROR_ACCOUNT_LOCKED_OUT
                    return "Account is locked out";
                case 1355: // ERROR_NO_SUCH_DOMAIN
                    return "Domain does not exist or cannot be contacted";
                case 1311: // ERROR_NO_SUCH_USER
                    return "Username does not exist in the specified domain";
                case 1909: // ERROR_ACCOUNT_EXPIRED
                    return "User account has expired";
                default:
                    return $"Logon failed with error code {errorCode}";
            }
        }

        // P/Invoke declarations for credential validation
        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeName(string lpSystemName, ref LUID lpLuid, StringBuilder lpName, ref int cchName);

        private const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
        private const int FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
        private const int FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
        private const int FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;

    private const int LOGON32_LOGON_INTERACTIVE = 2;
    private const int LOGON32_LOGON_BATCH = 4;
    private const int LOGON32_PROVIDER_DEFAULT = 0;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_PRIVILEGE_NOT_HELD = 1314;
        private const int ERROR_LOGON_TYPE_NOT_GRANTED = 1385;
        private const uint LOGON_WITH_PROFILE = 0x00000001;
        private const uint LOGON_NETCREDENTIALS_ONLY = 0x00000002;

        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private const uint TOKEN_ACCESS_FLAGS = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
        private const uint TOKEN_PRIVILEGE_ACCESS_FLAGS = TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES;

        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;

        private static readonly string[] CallerRequiredPrivileges = new[]
        {
            "SeImpersonatePrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege"
        };

        private static readonly Dictionary<string, string> PrivilegeFriendlyNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "SeImpersonatePrivilege", "Impersonate a client after authentication" },
            { "SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process" },
            { "SeProfileSingleProcessPrivilege", "Profile single process" },
            { "SeBackupPrivilege", "Back up files and directories" },
            { "SeRestorePrivilege", "Restore files and directories" }
        };

        private const uint STARTF_USESHOWWINDOW = 0x00000001;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const int SW_HIDE = 0;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;

        private const uint CREATE_UNICODE_ENVIRONMENT_FLAG = 0x00000400;
        private const uint CREATE_NO_WINDOW_FLAG = 0x08000000;

        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_FAILED = 0xFFFFFFFF;
        private const uint INFINITE = 0xFFFFFFFF;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int FormatMessage(int dwFlags, IntPtr lpSource, uint dwMessageId, int dwLanguageId, StringBuilder lpBuffer, int nSize, IntPtr Arguments);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            uint dwLogonFlags,
            string lpApplicationName,
            IntPtr lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL impersonationLevel,
            TOKEN_TYPE tokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            uint BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool UnloadUserProfile(IntPtr hToken, IntPtr hProfile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROFILEINFO
        {
            public int dwSize;
            public int dwFlags;
            public string lpUserName;
            public string lpProfilePath;
            public string lpDefaultPath;
            public string lpServerName;
            public string lpPolicyPath;
            public IntPtr hProfile;
        }

        public void Initialize()
        {
            Tracer.TraceInformation("*** INITIALIZING OUT-OF-PROCESS POWERSHELL 7+ ENGINE ***");
            Tracer.TraceInformation("powershell7-executable-path: {0}", powerShell7ExecutablePath);
            
            // Verify PowerShell 7 is available
            if (!File.Exists(powerShell7ExecutablePath))
            {
                string errorMessage = $"PowerShell 7+ executable not found at: {powerShell7ExecutablePath}";
                Tracer.TraceError($"powershell7-not-found: {errorMessage}");
                throw new FileNotFoundException(errorMessage);
            }

            // Verify PowerShell 7 version
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = powerShell7ExecutablePath;
                    process.StartInfo.Arguments = "-NoProfile -NonInteractive -Command \"Write-Output $PSVersionTable.PSVersion; Write-Output $PSVersionTable.PSEdition\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    
                    if (process.ExitCode == 0)
                    {
                        Tracer.TraceInformation("verified-powershell7-version-output: {0}", output.Trim());
                        Tracer.TraceInformation("*** OUT-OF-PROCESS POWERSHELL 7+ ENGINE INITIALIZED SUCCESSFULLY ***");
                    }
                    else
                    {
                        Tracer.TraceError($"powershell7-version-check-failed exit-code: {process.ExitCode}, error: {error}");
                        throw new InvalidOperationException($"PowerShell 7+ verification failed: {error}");
                    }
                }
            }
            catch (Exception ex)
            {
                Tracer.TraceError("failed-to-verify-powershell7-version", ex);
                throw new InvalidOperationException($"Failed to initialize PowerShell 7+ engine: {ex.Message}", ex);
            }
        }

        public void OpenRunspace()
        {
            Tracer.Enter("openrunspace-powershell7-outofprocess");
            try
            {
                // For out-of-process execution, we don't need to maintain a persistent runspace
                // Each script execution will create its own process
                Tracer.TraceInformation("*** OUT-OF-PROCESS POWERSHELL 7+ RUNSPACE READY ***");
                Tracer.TraceInformation("no-persistent-runspace-needed-for-out-of-process-execution");
                
                // Skip connectivity test to avoid AppDomain issues during initialization
                // The connectivity will be tested when the first script actually runs
                Tracer.TraceInformation("powershell7-runspace-opened-successfully-skipping-connectivity-test-to-avoid-appdomain-issues");
            }
            catch (Exception ex)
            {
                Tracer.TraceError("openrunspace-powershell7-outofprocess", ex);
                throw;
            }
            finally
            {
                Tracer.Exit("openrunspace-powershell7-outofprocess");
            }
        }

        public void CloseRunspace()
        {
            Tracer.Enter("closerunspace-powershell7-outofprocess");
            try
            {
                // Clean up session variables
                sessionVariables.Clear();
                Tracer.TraceInformation("*** OUT-OF-PROCESS POWERSHELL 7+ ENGINE CLEANED UP ***");
            }
            catch (Exception ex)
            {
                Tracer.TraceError("closerunspace-powershell7-outofprocess", ex);
                // Don't re-throw to allow graceful shutdown
            }
            finally
            {
                Tracer.Exit("closerunspace-powershell7-outofprocess");
            }
        }

        public Collection<PSObject> InvokePowerShellScript(Command command, PSDataCollection<PSObject> pipelineInput)
        {
            Tracer.Enter("invokepowershellscript-powershell7-outofprocess");
            try
            {
                // IMPORTANT: This is TRUE out-of-process PowerShell 7+ execution
                Tracer.TraceInformation("*** EXECUTING WITH TRUE OUT-OF-PROCESS POWERSHELL 7+ ENGINE ***");
                
                // Handle Command object properly - extract the script file path
                string scriptPath;
                
                if (command == null)
                {
                    throw new ArgumentNullException(nameof(command), "Command cannot be null");
                }
                
                // For PSMA, the command is typically created with new Command(scriptPath)
                // We need to extract the script path from the Command object
                // The CommandText property should be null, and we need to get the actual command name/path
                try
                {
                    // Try to access CommandText first (might contain the path)
                    if (!string.IsNullOrEmpty(command.CommandText))
                    {
                        scriptPath = command.CommandText;
                        Tracer.TraceInformation("powershell7-extracted-script-path-from-commandtext: {0}", scriptPath);
                    }
                    else
                    {
                        // Use reflection to get the command name/path since CommandName might not be accessible
                        var commandType = command.GetType();
                        var nameProperty = commandType.GetProperty("CommandName") ?? commandType.GetProperty("Name");
                        
                        if (nameProperty != null)
                        {
                            scriptPath = nameProperty.GetValue(command) as string;
                            Tracer.TraceInformation("powershell7-extracted-script-path-via-reflection: {0}", scriptPath);
                        }
                        else
                        {
                            // Last resort: convert command to string
                            scriptPath = command.ToString();
                            Tracer.TraceInformation("powershell7-extracted-script-path-via-tostring: {0}", scriptPath);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Tracer.TraceError($"powershell7-error-extracting-script-path: {ex.Message}");
                    throw new ArgumentException($"Failed to extract script path from Command object: {ex.Message}", nameof(command), ex);
                }
                
                if (string.IsNullOrEmpty(scriptPath))
                {
                    throw new ArgumentException("Command object contains no executable script path", nameof(command));
                }
                
                return ExecutePowerShellFile(scriptPath, command.Parameters, pipelineInput);
            }
            catch (Exception ex)
            {
                // Enhanced exception logging to help diagnose format string issues
                Tracer.TraceInformation("debug-invoke-exception-type: {0}", ex.GetType().Name);
                
                try
                {
                    Tracer.TraceError("invokepowershellscript-powershell7-outofprocess", ex);
                }
                catch (ArgumentOutOfRangeException aex)
                {
                    Tracer.TraceInformation("tracer-argumentoutofrange-in-invokepowershellscript: {0}", aex.Message);
                }
                
                throw;
            }
            finally
            {
                Tracer.Exit("invokepowershellscript-powershell7-outofprocess");
            }
        }

        private Collection<PSObject> ExecutePowerShellFile(string scriptPath, CommandParameterCollection parameters, PSDataCollection<PSObject> pipelineInput)
        {
            Collection<PSObject> results = new Collection<PSObject>();
            
            try
            {
                // Verify the script file exists
                if (!File.Exists(scriptPath))
                {
                    throw new FileNotFoundException($"PowerShell script file not found: {scriptPath}");
                }
                
                Tracer.TraceInformation("powershell7-executing-script-file: {0}", scriptPath);
                Tracer.TraceInformation("powershell7-script-parameters-count: {0}", parameters?.Count ?? 0);
                // Use in-memory stdin execution to eliminate temp file creation
                Tracer.TraceInformation("powershell7-using-in-memory-stdin-execution-for-script: {0}", scriptPath);
                
                var stdinContent = new StringBuilder();
                    stdinContent.AppendLine("# PSMA PowerShell 7 Engine In-Memory Execution");
                    stdinContent.AppendLine("# Set global variables to identify PowerShell 7 engine execution");
                    stdinContent.AppendLine("$global:PSMA_ENGINE = 'PowerShell7Engine'");
                    stdinContent.AppendLine("$global:PS7ENGINE = $true");
                    stdinContent.AppendLine("$global:PSMA_OUT_OF_PROCESS = $true");
                    stdinContent.AppendLine("");
                    
                    // Set additional engine identification variables for compatibility with Windows PowerShell 5.1
                    stdinContent.AppendLine("# Engine compatibility variables");
                    stdinContent.AppendLine("$global:PSMAEngineType = 'PowerShell 7+ (Out-of-Process)'");
                    stdinContent.AppendLine("$global:PSMAEngineVersion = '7.0'");
                    stdinContent.AppendLine("$global:PSMAEngineSelected = 'PowerShell 7+ (Out-of-Process)'");
                    stdinContent.AppendLine("");
                    
                    // Inject session variables (if any were set)
                    if (sessionVariables != null && sessionVariables.Count > 0)
                    {
                        stdinContent.AppendLine("# Session variables");
                        foreach (var variable in sessionVariables)
                        {
                            stdinContent.AppendLine("$global:" + variable.Key + " = " + ConvertToLiteral(variable.Value));
                        }
                        stdinContent.AppendLine("");
                    }
                    
                    // FIX: Inject pipeline input objects as $input variable
                    if (pipelineInput != null && pipelineInput.Count > 0)
                    {
                        stdinContent.AppendLine("# Pipeline input objects serialization");
                        stdinContent.AppendLine("$pipelineObjects = @()");
                        Tracer.TraceInformation("powershell7-serializing-pipeline-input-objects: {0}", pipelineInput.Count);
                        
                        int objectIndex = 0;
                        foreach (var psobject in pipelineInput)
                        {
                            objectIndex++;
                            if (psobject != null)
                            {
                                try
                                {
                                    // Serialize each pipeline object to recreate it in the child process
                                    string serializedObject = SerializePipelineObject(psobject);
                                    stdinContent.AppendLine($"# Pipeline object {objectIndex}");
                                    stdinContent.AppendLine("$pipelineObjects += " + serializedObject);
                                    Tracer.TraceInformation("powershell7-pipeline-object-serialized: {0} (length: {1})", objectIndex, serializedObject.Length);
                                }
                                catch (Exception ex)
                                {
                                    Tracer.TraceWarning("powershell7-pipeline-object-serialization-failed: object-{0}, error: {1}", objectIndex, ex.Message);
                                    // Add a null placeholder to maintain object count consistency
                                    stdinContent.AppendLine($"# Pipeline object {objectIndex} (serialization failed)");
                                    stdinContent.AppendLine("$pipelineObjects += $null");
                                }
                            }
                            else
                            {
                                stdinContent.AppendLine($"# Pipeline object {objectIndex} (null)");
                                stdinContent.AppendLine("$pipelineObjects += $null");
                            }
                        }
                        
                        // Set up $input variable to make pipeline objects available to the script
                        stdinContent.AppendLine("");
                        stdinContent.AppendLine("# Make pipeline objects available as $input automatic variable");
                        stdinContent.AppendLine("$input = $pipelineObjects");
                        stdinContent.AppendLine($"Write-Host 'PSMA: Injected {pipelineInput.Count} pipeline objects into PowerShell 7 execution'");
                        stdinContent.AppendLine("");
                        
                        Tracer.TraceInformation("powershell7-pipeline-input-injection-complete: {0} objects", pipelineInput.Count);
                    }
                    else
                    {
                        Tracer.TraceInformation("powershell7-no-pipeline-input-objects-to-inject");
                        stdinContent.AppendLine("# No pipeline input objects");
                        stdinContent.AppendLine("$input = @()");
                        stdinContent.AppendLine("");
                    }
                    
                    // Define all parameters directly in stdin script
                    if (parameters != null)
                    {
                        foreach (CommandParameter param in parameters)
                        {
                            if (param.Value != null)
                            {
                                string escapedValue = EscapeParameterValue(param.Value);
                                stdinContent.AppendLine("# Parameter: " + param.Name);
                                stdinContent.AppendLine("$" + param.Name + " = " + escapedValue);
                                Tracer.TraceInformation("stdin-parameter-defined: -{0} (length: {1})", param.Name, escapedValue.Length);
                            }
                            else
                            {
                                // Check if this is a credential/password parameter that should be null, not a switch
                                if (param.Name.Contains("Password") || param.Name.Contains("Credential"))
                                {
                                    stdinContent.AppendLine("# Null credential parameter: " + param.Name);
                                    stdinContent.AppendLine("$" + param.Name + " = $null");
                                    Tracer.TraceInformation("stdin-null-credential-parameter-defined: -{0}", param.Name);
                                }
                                else
                                {
                                    stdinContent.AppendLine("# Switch parameter: " + param.Name);
                                    stdinContent.AppendLine("$" + param.Name + " = $true");
                                    Tracer.TraceInformation("stdin-switch-parameter-defined: -{0}", param.Name);
                                }
                            }
                        }
                    }
                    
                    stdinContent.AppendLine("");
                    stdinContent.AppendLine($"# Execute the actual script using call operator with pipeline objects: {scriptPath}");
                    
                    // Build the call operator command with all parameters as variables
                    var scriptInvocation = new StringBuilder();
                    scriptInvocation.Append("& \"" + scriptPath + "\"");
                    
                    // Add all parameters as variables (no command line length limits with stdin)
                    if (parameters != null)
                    {
                        foreach (var param in parameters)
                        {
                            scriptInvocation.Append(" -" + param.Name + " $" + param.Name);
                        }
                    }
                    
                    // FIX: Execute script with pipeline objects piped to it
                    // PowerShell 7 requires transformation of BEGIN/PROCESS/END blocks to work with pipeline input
                    stdinContent.AppendLine("$allOutput = & {");
                    if (pipelineInput != null && pipelineInput.Count > 0)
                    {
                        stdinContent.AppendLine("    # Read and transform user script to work with PowerShell 7 pipeline");
                        stdinContent.AppendLine("    $userScriptContent = Get-Content -Path '" + scriptPath.Replace("'", "''").Replace("\\", "\\\\") + "' -Raw");
                        stdinContent.AppendLine("    ");
                        stdinContent.AppendLine("    # Extract BEGIN, PROCESS, and END blocks using improved regex");
                        stdinContent.AppendLine("    # Match BEGIN/PROCESS/END keywords with optional whitespace and braces");
                        stdinContent.AppendLine("    $beginMatch = [regex]::Match($userScriptContent, '(?si)\\bBEGIN\\s*\\{')");
                        stdinContent.AppendLine("    $processMatch = [regex]::Match($userScriptContent, '(?si)\\bPROCESS\\s*\\{')");  
                        stdinContent.AppendLine("    $endMatch = [regex]::Match($userScriptContent, '(?si)\\bEND\\s*\\{')");
                        stdinContent.AppendLine("    ");
                        stdinContent.AppendLine("    # Debug: Log what was detected");
                        stdinContent.AppendLine("    Write-Host \"DEBUG: BEGIN detected: $($beginMatch.Success)\"");
                        stdinContent.AppendLine("    Write-Host \"DEBUG: PROCESS detected: $($processMatch.Success)\"");
                        stdinContent.AppendLine("    Write-Host \"DEBUG: END detected: $($endMatch.Success)\"");
                        stdinContent.AppendLine("    ");
                        stdinContent.AppendLine("    # If script has BEGIN/PROCESS/END structure, execute it properly");
                        stdinContent.AppendLine("    if ($beginMatch.Success -and $processMatch.Success) {");
                        stdinContent.AppendLine("        Write-Host \"DEBUG: Using structured BEGIN/PROCESS/END execution\"");
                        stdinContent.AppendLine("        # For structured scripts, pipe objects directly to the script");
                        stdinContent.AppendLine("        $pipelineObjects | & '" + scriptPath.Replace("'", "''").Replace("\\", "\\\\") + "'");
                        stdinContent.AppendLine("    }");
                        stdinContent.AppendLine("    ");
                        stdinContent.AppendLine("    elseif ($processMatch.Success) {");
                        stdinContent.AppendLine("        Write-Host \"DEBUG: Script has PROCESS block but no BEGIN - executing with pipeline\"");
                        stdinContent.AppendLine("        # Script has PROCESS but no BEGIN - still pipe to it");
                        stdinContent.AppendLine("        $pipelineObjects | & '" + scriptPath.Replace("'", "''").Replace("\\", "\\\\") + "'");
                        stdinContent.AppendLine("    } else {");
                        stdinContent.AppendLine("        Write-Host \"DEBUG: No structured blocks detected - executing script for each object with dot sourcing\"");
                        stdinContent.AppendLine("        # No structured blocks detected, execute script for each object");
                        stdinContent.AppendLine("        $pipelineObjects | ForEach-Object {");
                        stdinContent.AppendLine("            $currentObject = $_");
                        stdinContent.AppendLine("            & { ");
                        stdinContent.AppendLine("                param($currentObj, $scriptPath)");
                        stdinContent.AppendLine("                $_ = $currentObj");
                        stdinContent.AppendLine("                # Use dot sourcing instead of Invoke-Expression for complex scripts");
                        stdinContent.AppendLine("                . $scriptPath");
                        stdinContent.AppendLine("            } $currentObject '" + scriptPath.Replace("'", "''").Replace("\\", "\\\\") + "'");
                        stdinContent.AppendLine("        }");
                        stdinContent.AppendLine("    }");
                        stdinContent.AppendLine("    ");
                        stdinContent.AppendLine("    # Execute END block once if it exists");
                        stdinContent.AppendLine("    if ($endMatch.Success) {");
                        stdinContent.AppendLine("        $endCode = $endMatch.Groups[1].Value");
                        stdinContent.AppendLine("        Invoke-Expression $endCode");
                        stdinContent.AppendLine("    }");
                    }
                    else
                    {
                        stdinContent.AppendLine("    # No pipeline objects - execute script directly");
                        stdinContent.AppendLine("    " + scriptInvocation.ToString());
                    }
                    stdinContent.AppendLine("}");
                    stdinContent.AppendLine("");
                    stdinContent.AppendLine("# Convert all output objects to consistent format for parsing");
                    stdinContent.AppendLine("if ($allOutput) {");
                    stdinContent.AppendLine("    foreach ($obj in $allOutput) {");
                    stdinContent.AppendLine("        if ($null -eq $obj) {");
                    stdinContent.AppendLine("            # Skip null objects");
                    stdinContent.AppendLine("            continue");
                    stdinContent.AppendLine("        }");
                    stdinContent.AppendLine("        ");
                    stdinContent.AppendLine("        Write-Host \"PSMA_OBJECT_START\"");
                    stdinContent.AppendLine("        ");
                    stdinContent.AppendLine("        if ($obj -is [hashtable]) {");
                    stdinContent.AppendLine("            # Handle hashtable objects - output as key=value pairs");
                    stdinContent.AppendLine("            foreach ($key in $obj.Keys) {");
                    stdinContent.AppendLine("                $value = $obj[$key]");
                    stdinContent.AppendLine("                if ($null -eq $value) { ");
                    stdinContent.AppendLine("                    $typeNameOfValue = 'System.Object'");
                    stdinContent.AppendLine("                    $valueStr = ''");
                    stdinContent.AppendLine("                } else {");
                    stdinContent.AppendLine("                    $typeNameOfValue = $value.GetType().FullName");
                    stdinContent.AppendLine("                    if ($value -is [bool]) {");
                    stdinContent.AppendLine("                        $valueStr = if ($value) { 'True' } else { 'False' }");
                    stdinContent.AppendLine("                    } elseif ($value -is [int] -or $value -is [double] -or $value -is [decimal]) {");
                    stdinContent.AppendLine("                        $valueStr = $value.ToString()");
                    stdinContent.AppendLine("                    } elseif ($value -is [string]) {");
                    stdinContent.AppendLine("                        $valueStr = $value.ToString()");
                    stdinContent.AppendLine("                    } else {");
                    stdinContent.AppendLine("                        $valueStr = ConvertTo-Json $value -Compress");
                    stdinContent.AppendLine("                    }");
                    stdinContent.AppendLine("                }");
                    stdinContent.AppendLine("                Write-Host ($typeNameOfValue + '|' + $key + '=' + $valueStr)");
                    stdinContent.AppendLine("            }");
                    stdinContent.AppendLine("        } elseif ($obj -is [PSCustomObject] -or $obj.GetType().Name -eq 'PSObject') {");
                    stdinContent.AppendLine("            # Handle PSObject/PSCustomObject - convert to hashtable format");
                    stdinContent.AppendLine("            $obj.PSObject.Properties | ForEach-Object {");
                    stdinContent.AppendLine("                $value = $_.Value");
                    stdinContent.AppendLine("                if ($null -eq $value) { $value = ''; $typeNameOfValue = 'System.Object' } else { $typeNameOfValue = $_.TypeNameOfValue; $value = ConvertTo-Json $value -Compress }");
                    stdinContent.AppendLine("                Write-Host ($typeNameOfValue + '|' + $_.Name + '=' + $value)");
                    stdinContent.AppendLine("            }");
                    stdinContent.AppendLine("        } else {");
                    stdinContent.AppendLine("            # Handle other object types - try to convert to hashtable-like format");
                    stdinContent.AppendLine("            try {");
                    stdinContent.AppendLine("                $properties = $obj | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name");
                    stdinContent.AppendLine("                if ($properties) {");
                    stdinContent.AppendLine("                    foreach ($prop in $properties) {");
                    stdinContent.AppendLine("                        $value = $obj.$prop");
                    stdinContent.AppendLine("                        if ($null -eq $value) { $value = ''; $typeNameOfValue = 'System.Object' } else { $typeNameOfValue = $value.GetType().FullName; $value = ConvertTo-Json $value -Compress }");
                    stdinContent.AppendLine("                        Write-Host ($typeNameOfValue + '|' + $prop + '=' + $value)");
                    stdinContent.AppendLine("                    }");
                    stdinContent.AppendLine("                } else {");
                    stdinContent.AppendLine("                    # Object has no discoverable properties, use string representation");
                    stdinContent.AppendLine("                    Write-Host ('System.String|_ObjectValue=' + $obj)");
                    stdinContent.AppendLine("                }");
                    stdinContent.AppendLine("            } catch {");
                    stdinContent.AppendLine("                # Fallback: use string representation");
                    stdinContent.AppendLine("                Write-Host ('System.String|_ObjectValue=' + $obj)");
                    stdinContent.AppendLine("            }");
                    stdinContent.AppendLine("        }");
                    stdinContent.AppendLine("        ");
                    stdinContent.AppendLine("        Write-Host \"PSMA_OBJECT_END\"");
                    stdinContent.AppendLine("    }");
                    stdinContent.AppendLine("}");
                    
                    // Capture important global variables after script execution
                    stdinContent.AppendLine("");
                    stdinContent.AppendLine("# Capture global variables for PSMA engine");
                    stdinContent.AppendLine("Write-Host \"PSMA_VAR_START\"");
                    stdinContent.AppendLine("if ($null -ne $global:MoreToImport) { Write-Host \"MoreToImport=$global:MoreToImport\" }");
                    stdinContent.AppendLine("if ($null -ne $global:RunStepCustomData) { Write-Host \"RunStepCustomData=$global:RunStepCustomData\" }");
                    stdinContent.AppendLine("if ($null -ne $global:PageToken) { Write-Host \"PageToken=$global:PageToken\" }");
                    stdinContent.AppendLine("Write-Host \"PSMA_VAR_END\"");
                    
                    Tracer.TraceInformation("powershell7-stdin-content-prepared-length: {0}", stdinContent.Length);
                
                    // Execute PowerShell 7+ process with the wrapper script
                    using (var process = new Process())
                    {
                        process.StartInfo.FileName = powerShell7ExecutablePath;
                        
                        // Build arguments for stdin execution (no temp file needed)
                        var argumentsBuilder = new StringBuilder();
                        argumentsBuilder.Append("-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -");
                        
                        // No parameters on command line - all parameters are in stdin content
                        Tracer.TraceInformation("using-stdin-execution-no-command-line-parameters-needed");
                    
                    string powershellArguments = argumentsBuilder.ToString();
                    process.StartInfo.Arguments = powershellArguments;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardInput = true;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;
                    
                    // Set working directory to a location accessible by the impersonated user
                    // Avoid using the service user's temp directory when impersonating
                    process.StartInfo.WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    
                    // Configure impersonation if credentials are provided
                    var impersonationUsername = GetVariable("_ImpersonationUsername") as string;
                    var impersonationDomain = GetVariable("_ImpersonationDomain") as string;
                    var impersonationPassword = GetVariable("_ImpersonationPassword") as string;
                    
                    bool impersonationConfigured = false;
                    if (!string.IsNullOrEmpty(impersonationUsername) && !string.IsNullOrEmpty(impersonationPassword))
                    {
                        try
                        {
                            Tracer.TraceInformation("configuring-powershell7-process-with-impersonation domain: '{0}', username: '{1}'", impersonationDomain ?? "", impersonationUsername);
                            
                            // Configure process to run under specified credentials
                            process.StartInfo.UserName = impersonationUsername;
                            process.StartInfo.Domain = impersonationDomain ?? "";
                            
                            // Convert password to SecureString
                            var securePassword = new System.Security.SecureString();
                            foreach (char c in impersonationPassword)
                            {
                                securePassword.AppendChar(c);
                            }
                            securePassword.MakeReadOnly();
                            process.StartInfo.Password = securePassword;
                            
                            // Required for impersonation
                            process.StartInfo.LoadUserProfile = true;
                            impersonationConfigured = true;
                            
                            Tracer.TraceInformation("powershell7-process-configured-for-impersonation");
                        }
                        catch (Exception ex)
                        {
                            Tracer.TraceError($"failed-to-configure-powershell7-impersonation: {ex.Message}");
                            throw new System.Security.SecurityException($"Failed to configure PowerShell 7+ impersonation: {ex.Message}. Verify the credentials are correct and the account has the required permissions.", ex);
                        }
                    }
                    
                    if (!impersonationConfigured)
                    {
                        Tracer.TraceInformation("powershell7-will-run-as-sync-service-account");
                    }
                    
                    // Set session variables as environment variables for the process
                    // Environment variables are now injected via helper to ensure impersonated users inherit correctly
                    
                    Tracer.TraceInformation("starting-powershell7-process: {0} {1}", process.StartInfo.FileName?.Replace("{", "{{").Replace("}", "}}"), process.StartInfo.Arguments?.Replace("{", "{{").Replace("}", "}}"));
                    Tracer.TraceInformation("working-directory: {0}", process.StartInfo.WorkingDirectory);
                    Tracer.TraceInformation("impersonation-configured: {0}", impersonationConfigured);
                    
                    // Additional debug info for 0xc0000142 troubleshooting
                    Tracer.TraceInformation("powershell7-executable-exists: {0}", File.Exists(process.StartInfo.FileName));
                    // No wrapper script file - using stdin execution
                    Tracer.TraceInformation("stdin-content-size: {0} bytes", stdinContent.Length);
                    Tracer.TraceInformation("process-env-vars-count: {0}", process.StartInfo.EnvironmentVariables.Count);

                    // EXTRA DEBUG: capture current process identity and environment snapshot before starting pwsh
                    try
                    {
                        var currentIdentity = System.Security.Principal.WindowsIdentity.GetCurrent();
                        Tracer.TraceInformation("current-process-identity: {0}", currentIdentity?.Name ?? "<unknown>");
                    }
                    catch (Exception idEx)
                    {
                        Tracer.TraceWarning($"failed-to-get-current-identity: {idEx.Message}");
                    }

                    try
                    {
                        var parentProc = Process.GetCurrentProcess();
                        Tracer.TraceInformation("parent-process-name: {0}, id: {1}", parentProc.ProcessName, parentProc.Id);
                    }
                    catch (Exception pex)
                    {
                        Tracer.TraceWarning($"failed-to-get-parent-process-info: {pex.Message}");
                    }

                    try
                    {
                        var pathEnv = process.StartInfo.EnvironmentVariables.ContainsKey("PATH") ? process.StartInfo.EnvironmentVariables["PATH"] : null;
                        var psModulePath = process.StartInfo.EnvironmentVariables.ContainsKey("PSModulePath") ? process.StartInfo.EnvironmentVariables["PSModulePath"] : null;
                        Tracer.TraceInformation("child-process-PATH-length: {0}", pathEnv?.Length ?? 0);
                        Tracer.TraceInformation("child-process-PSModulePath-length: {0}", psModulePath?.Length ?? 0);
                    }
                    catch (Exception envEx)
                    {
                        Tracer.TraceWarning($"failed-to-read-environment-variables: {envEx.Message}");
                    }

                    Tracer.TraceInformation("process-startinfo-loaduserprofile: {0}", process.StartInfo.LoadUserProfile);

                    // Ensure environment variables ready for impersonated process
                    var inheritedEnvironment = BuildEnvironment(process.StartInfo.EnvironmentVariables, impersonationConfigured);
                    
                    // ENHANCED DEBUG: Log complete process configuration
                    Tracer.TraceInformation("*** ENHANCED POWERSHELL 7 PROCESS DEBUG ***");
                    Tracer.TraceInformation("process-filename: '{0}'", process.StartInfo.FileName);
                    Tracer.TraceInformation("process-arguments: '{0}'", process.StartInfo.Arguments);
                    Tracer.TraceInformation("script-file-exists: {0}", File.Exists(scriptPath));
                    Tracer.TraceInformation("script-file-size: {0} bytes", new FileInfo(scriptPath).Length);
                    Tracer.TraceInformation("use-shell-execute: {0}", process.StartInfo.UseShellExecute);
                    Tracer.TraceInformation("redirect-stdout: {0}", process.StartInfo.RedirectStandardOutput);
                    Tracer.TraceInformation("redirect-stderr: {0}", process.StartInfo.RedirectStandardError);
                    
                    try
                    {
                        Tracer.TraceInformation("starting-powershell7-process-with-enhanced-error-handling");

                        // If impersonation is configured, try PowerShell Job approach as fallback for service context issues
                        if (impersonationConfigured)
                        {
                            Tracer.TraceInformation("attempting-powershell7-impersonation-with-job-fallback-strategy");
                            
                            try
                            {
                                // First attempt: Standard ProcessStartInfo approach
                                var processResult = ExecuteWithProcessStartInfo(process, stdinContent.ToString());
                                if (processResult.Success)
                                {
                                    Tracer.TraceInformation("powershell7-process-startinfo-impersonation-successful");
                                    return processResult.Results;
                                }
                                else
                                {
                                    Tracer.TraceWarning("powershell7-process-startinfo-failed-exit-code: {0}, attempting-job-fallback", 0, EscapeForTrace(processResult.ExitCodeDescription ?? processResult.ExitCode.ToString()));
                                    
                                    // Second attempt: PowerShell Jobs approach for service context compatibility
                                    if (processResult.ExitCode == -1073741502) // 0xc0000142 - Application initialization failure
                                    {
                                        Tracer.TraceInformation("detected-service-context-impersonation-issue-attempting-token-launch");
                                        var tokenResult = ExecuteWithCreateProcessWithTokenAndCompatibility(impersonationUsername, impersonationDomain, impersonationPassword, powerShell7ExecutablePath, powershellArguments, process.StartInfo.WorkingDirectory ?? Environment.CurrentDirectory, inheritedEnvironment);
                                        if (tokenResult.Success)
                                        {
                                            Tracer.TraceInformation("powershell7-token-launch-successful");
                                            return tokenResult.Results;
                                        }

                                        Tracer.TraceWarning("powershell7-token-launch-failed error:{0}", 0, EscapeForTrace(tokenResult.ErrorMessage));
                                        Tracer.TraceInformation("falling-back-to-job-launch");
                                        var jobResult = ExecuteWithPowerShellJob(stdinContent.ToString(), impersonationUsername, impersonationDomain, impersonationPassword);
                                        if (jobResult.Success)
                                        {
                                            Tracer.TraceInformation("powershell7-job-impersonation-successful");
                                            return jobResult.Results;
                                        }
                                        else
                                        {
                                            Tracer.TraceError("powershell7-job-impersonation-also-failed: {0}", 0, EscapeForTrace(jobResult.ErrorMessage));
                                            throw new InvalidOperationException($"PowerShell 7+ impersonation failed with ProcessStartInfo, CreateProcessWithToken, and Job approaches. ProcessStartInfo error: {processResult.ErrorMessage}. Token error: {tokenResult.ErrorMessage}. Job error: {jobResult.ErrorMessage}");
                                        }
                                    }
                                    else
                                    {
                                        throw new InvalidOperationException($"PowerShell 7+ process failed with exit code detail: {processResult.ErrorMessage}");
                                    }
                                }
                            }
                            catch (Exception impEx)
                            {
                                Tracer.TraceError("powershell7-impersonation-strategies-failed", impEx);
                                throw;
                            }
                        }
                        else
                        {
                            // No impersonation - use standard approach
                            var result = ExecuteWithProcessStartInfo(process, stdinContent.ToString());
                            if (result.Success)
                            {
                                return result.Results;
                            }
                            else
                            {
                                throw new InvalidOperationException($"PowerShell 7+ process failed with exit code detail: {result.ErrorMessage}");
                            }
                        }


                    }
                    catch (System.ComponentModel.Win32Exception win32Ex)
                    {
                        Tracer.TraceError($"powershell7-process-start-win32-error: {win32Ex.Message} (Code: {win32Ex.NativeErrorCode})");
                        
                        // Provide specific error messages for common impersonation issues
                        string errorMessage;
                        switch (win32Ex.NativeErrorCode)
                        {
                            case 1326:
                                errorMessage = "Failed to start PowerShell 7+ process: Invalid username or password for impersonation.";
                                break;
                            case 1331:
                                errorMessage = "Failed to start PowerShell 7+ process: Account restrictions prevent impersonation (account may be disabled or locked).";
                                break;
                            case 1332:
                                errorMessage = "Failed to start PowerShell 7+ process: Account is locked out.";
                                break;
                            case 1355:
                                errorMessage = "Failed to start PowerShell 7+ process: Domain does not exist or cannot be contacted.";
                                break;
                            case 5:
                                errorMessage = "Failed to start PowerShell 7+ process: Access denied. The impersonation account may not have the required 'Log on as a service' right.";
                                break;
                            default:
                                errorMessage = $"Failed to start PowerShell 7+ process: {win32Ex.Message} (Code: {win32Ex.NativeErrorCode})";
                                break;
                        }
                        
                        if (impersonationConfigured)
                        {
                            errorMessage += " Please verify the impersonation credentials and account permissions.";
                        }
                        
                        throw new System.Security.SecurityException(errorMessage, win32Ex);
                    }
                }
            }
            catch (Exception ex)
            {
                // Enhanced exception logging to help diagnose format string issues
                Tracer.TraceInformation("debug-exception-type: {0}", ex.GetType().Name);
                Tracer.TraceInformation("debug-exception-message-length: {0}", ex.Message?.Length ?? 0);
                Tracer.TraceInformation("debug-exception-source: {0}", ex.Source ?? "null");
                
                try
                {
                    Tracer.TraceError("ExecutePowerShellFile-error", ex);
                }
                catch (ArgumentOutOfRangeException aex)
                {
                    Tracer.TraceInformation("tracer-argumentoutofrange-in-executepowershellfile: {0}", aex.Message);
                }
                
                throw new InvalidOperationException($"Unexpected error during PowerShell 7+ execution: {ex.Message}", ex);
            }
            finally
            {
                // No temp file cleanup needed - using in-memory stdin execution
            }
        }

        private PrivilegeCheckResult EvaluateCallerPrivilegeRequirements()
        {
            var result = new PrivilegeCheckResult
            {
                RequiredPrivileges = CallerRequiredPrivileges
            };

            var states = GetCurrentPrivilegeStates(out string failureReason);

            if (states == null)
            {
                result.QuerySucceeded = false;
                if (!string.IsNullOrEmpty(failureReason))
                {
                    result.Diagnostics.Add(failureReason);
                }
                return result;
            }

            result.QuerySucceeded = true;

            foreach (var privilege in CallerRequiredPrivileges)
            {
                PrivilegeState state;
                bool present = states.TryGetValue(privilege, out state);
                bool enabled = present && state.Enabled;
                bool enabledByDefault = present && state.EnabledByDefault;

                result.Diagnostics.Add($"privilege-status {privilege}: present={present}, enabled={enabled}, enabled-by-default={enabledByDefault}");

                if (!present)
                {
                    result.MissingPrivileges.Add(privilege);
                }
                else if (!enabled)
                {
                    result.DisabledPrivileges.Add(privilege);
                }
            }

            result.HasAllRequired = result.MissingPrivileges.Count == 0 && result.DisabledPrivileges.Count == 0;

            if (result.HasAllRequired)
            {
                result.Diagnostics.Add("privilege-status summary: all required caller privileges are enabled.");
            }

            return result;
        }

        private Dictionary<string, PrivilegeState> GetCurrentPrivilegeStates(out string failureReason)
        {
            failureReason = null;
            var privileges = new Dictionary<string, PrivilegeState>(StringComparer.OrdinalIgnoreCase);
            IntPtr tokenHandle = IntPtr.Zero;

            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out tokenHandle))
                {
                    int error = Marshal.GetLastWin32Error();
                    failureReason = $"OpenProcessToken failed: {FormatWin32ErrorMessage(error)}";
                    return null;
                }

                int requiredLength;
                if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out requiredLength))
                {
                    int sizeError = Marshal.GetLastWin32Error();
                    if (sizeError != ERROR_INSUFFICIENT_BUFFER)
                    {
                        failureReason = $"GetTokenInformation (size) failed: {FormatWin32ErrorMessage(sizeError)}";
                        return null;
                    }
                }

                IntPtr buffer = Marshal.AllocHGlobal(requiredLength);
                try
                {
                    if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, buffer, requiredLength, out requiredLength))
                    {
                        int dataError = Marshal.GetLastWin32Error();
                        failureReason = $"GetTokenInformation (data) failed: {FormatWin32ErrorMessage(dataError)}";
                        return null;
                    }

                    uint privilegeCount = (uint)Marshal.ReadInt32(buffer);
                    if (privilegeCount == 0)
                    {
                        return privileges;
                    }

                    IntPtr current = IntPtr.Add(buffer, sizeof(uint));
                    int luidAndAttrSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));

                    for (int i = 0; i < privilegeCount; i++)
                    {
                        var luidAttributes = Marshal.PtrToStructure<LUID_AND_ATTRIBUTES>(IntPtr.Add(current, i * luidAndAttrSize));

                        var lookupLuid = luidAttributes.Luid;
                        int nameLength = 0;
                        LookupPrivilegeName(null, ref lookupLuid, null, ref nameLength);
                        int initialLookupError = Marshal.GetLastWin32Error();
                        if (initialLookupError != ERROR_INSUFFICIENT_BUFFER || nameLength <= 0)
                        {
                            Tracer.TraceWarning("privilege-lookup-initial-failed luid-low:{0} error:{1}", 0, luidAttributes.Luid.LowPart, FormatWin32ErrorMessage(initialLookupError));
                            continue;
                        }

                        var nameBuilder = new StringBuilder(nameLength + 1);
                        lookupLuid = luidAttributes.Luid;
                        if (!LookupPrivilegeName(null, ref lookupLuid, nameBuilder, ref nameLength))
                        {
                            int nameError = Marshal.GetLastWin32Error();
                            Tracer.TraceWarning("privilege-lookup-final-failed luid-low:{0} error:{1}", 0, luidAttributes.Luid.LowPart, FormatWin32ErrorMessage(nameError));
                            continue;
                        }

                        string privilegeName = nameBuilder.ToString();

                        privileges[privilegeName] = new PrivilegeState
                        {
                            Present = true,
                            Enabled = (luidAttributes.Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED,
                            EnabledByDefault = (luidAttributes.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) == SE_PRIVILEGE_ENABLED_BY_DEFAULT
                        };
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                failureReason = $"Exception while enumerating caller privileges: {ex.Message}";
                return null;
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    CloseHandleSafe(tokenHandle);
                }
            }

            return privileges;
        }

        private static string FormatPrivilegeDisplay(string privilege)
        {
            if (PrivilegeFriendlyNames.TryGetValue(privilege, out var friendly))
            {
                return $"{friendly} ({privilege})";
            }

            return privilege;
        }

        private string BuildPrivilegeGuidanceMessage(string context, PrivilegeCheckResult privilegeCheck, int? win32Error = null, string failingOperation = null)
        {
            var sb = new StringBuilder();

            if (!string.IsNullOrWhiteSpace(context))
            {
                sb.Append(context.Trim());
                if (!context.TrimEnd().EndsWith("."))
                {
                    sb.Append('.');
                }
                sb.Append(' ');
            }

            if (win32Error.HasValue)
            {
                sb.AppendFormat("{0} failed with error {1} ({2}). ", failingOperation ?? "The operation", win32Error.Value, FormatWin32ErrorMessage(win32Error.Value));
            }

            var required = privilegeCheck?.RequiredPrivileges ?? CallerRequiredPrivileges;
            sb.Append("PowerShell 7 impersonation requires the Synchronization Service account to hold and have enabled: ");
            sb.Append(string.Join(", ", required.Select(FormatPrivilegeDisplay)));
            sb.Append(". ");

            if (privilegeCheck != null)
            {
                if (privilegeCheck.QuerySucceeded)
                {
                    if (privilegeCheck.MissingPrivileges.Any())
                    {
                        sb.Append("Missing: ");
                        sb.Append(string.Join(", ", privilegeCheck.MissingPrivileges.Select(FormatPrivilegeDisplay)));
                        sb.Append(". ");
                    }

                    if (privilegeCheck.DisabledPrivileges.Any())
                    {
                        sb.Append("Disabled: ");
                        sb.Append(string.Join(", ", privilegeCheck.DisabledPrivileges.Select(FormatPrivilegeDisplay)));
                        sb.Append(". ");
                    }

                    if (privilegeCheck.HasAllRequired && !win32Error.HasValue)
                    {
                        sb.Append("All required rights appear enabled. Confirm the Microsoft Identity Manager Synchronization Service runs under LocalSystem or an account with local administrator privileges, because LoadUserProfile requires administrator context. ");
                    }
                }
                else
                {
                    sb.Append("The current process privileges could not be enumerated automatically. Run 'whoami /priv' under the Synchronization Service account to verify each right is assigned and enabled. ");
                }
            }

            sb.Append("Assign the rights via Local Security Policy or Group Policy, restart the Synchronization Service, and retry. See the README section \"PowerShell 7 impersonation prerequisites\" for detailed instructions.");

            return sb.ToString().Trim();
        }

        /// <summary>
        /// Attempts to enable required privileges that are present but not enabled
        /// </summary>
        private bool TryEnableRequiredPrivileges(out string errorMessage)
        {
            errorMessage = null;
            IntPtr tokenHandle = IntPtr.Zero;

            try
            {
                Tracer.TraceInformation("attempting-to-enable-required-privileges");

                // Open current process token with privilege adjustment rights
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_PRIVILEGE_ACCESS_FLAGS, out tokenHandle))
                {
                    int error = Marshal.GetLastWin32Error();
                    errorMessage = $"Failed to open process token for privilege adjustment: {FormatWin32ErrorMessage(error)}";
                    return false;
                }

                bool anyEnabled = false;
                foreach (string privilege in CallerRequiredPrivileges)
                {
                    if (TryEnablePrivilege(tokenHandle, privilege))
                    {
                        Tracer.TraceInformation($"privilege-enabled-successfully: {privilege}");
                        anyEnabled = true;
                    }
                    else
                    {
                        Tracer.TraceWarning($"privilege-enable-failed: {privilege}");
                    }
                }

                if (anyEnabled)
                {
                    Tracer.TraceInformation("privilege-enablement-completed-some-enabled");
                    return true;
                }
                else
                {
                    errorMessage = "No privileges could be enabled. They may not be assigned to this account or may already be enabled.";
                    return false;
                }
            }
            catch (Exception ex)
            {
                errorMessage = $"Exception during privilege enablement: {ex.Message}";
                return false;
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    CloseHandle(tokenHandle);
                }
            }
        }

        /// <summary>
        /// Attempts to enable a specific privilege
        /// </summary>
        private bool TryEnablePrivilege(IntPtr tokenHandle, string privilegeName)
        {
            try
            {
                // Look up the privilege LUID
                if (!LookupPrivilegeValue(null, privilegeName, out LUID privilegeLuid))
                {
                    int error = Marshal.GetLastWin32Error();
                    Tracer.TraceWarning($"privilege-lookup-failed: {privilegeName} - {FormatWin32ErrorMessage(error)}");
                    return false;
                }

                // Build the TOKEN_PRIVILEGES structure
                var tokenPrivileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES
                    {
                        Luid = privilegeLuid,
                        Attributes = SE_PRIVILEGE_ENABLED
                    }
                };

                // Adjust the token privileges
                if (!AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();
                    Tracer.TraceWarning($"privilege-adjust-failed: {privilegeName} - {FormatWin32ErrorMessage(error)}");
                    return false;
                }

                // Check if the privilege was actually enabled (AdjustTokenPrivileges can return true but not enable the privilege)
                int lastError = Marshal.GetLastWin32Error();
                if (lastError == 1300) // ERROR_NOT_ALL_ASSIGNED
                {
                    Tracer.TraceWarning($"privilege-not-assigned: {privilegeName} - privilege is not assigned to this account");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Tracer.TraceError($"privilege-enable-exception: {privilegeName} - {ex.Message}");
                return false;
            }
        }

        private Dictionary<string, string> BuildEnvironment(StringDictionary baseEnvironment, bool impersonationConfigured)
        {
            var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (baseEnvironment != null)
            {
                foreach (string key in baseEnvironment.Keys)
                {
                    environment[key] = baseEnvironment[key];
                }

                baseEnvironment.Clear();
            }
            else
            {
                foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
                {
                    environment[entry.Key.ToString()] = entry.Value?.ToString() ?? string.Empty;
                }
            }

            if (sessionVariables != null && sessionVariables.Count > 0)
            {
                foreach (var variable in sessionVariables)
                {
                    if (variable.Key.StartsWith("_Impersonation"))
                    {
                        continue;
                    }

                    string envKey = $"PSMA_{variable.Key}";
                    string envValue = variable.Value?.ToString() ?? string.Empty;
                    environment[envKey] = envValue;
                    Tracer.TraceInformation("powershell7-set-environment-variable: {0} = {1}", envKey, EscapeForTrace(envValue));
                }
            }

            if (baseEnvironment != null)
            {
                foreach (var kvp in environment)
                {
                    baseEnvironment[kvp.Key] = kvp.Value ?? string.Empty;
                }
            }

            if (impersonationConfigured && !environment.ContainsKey("TEMP"))
            {
                string temp = Environment.GetEnvironmentVariable("TEMP") ?? Environment.GetEnvironmentVariable("TMP") ?? @"C:\Windows\Temp";
                environment["TEMP"] = temp;
            }

            if (impersonationConfigured && !environment.ContainsKey("TMP"))
            {
                string tmp = Environment.GetEnvironmentVariable("TMP") ?? Environment.GetEnvironmentVariable("TEMP") ?? @"C:\Windows\Temp";
                environment["TMP"] = tmp;
            }

            return environment;
        }

        private class PrivilegeState
        {
            public bool Present { get; set; }
            public bool Enabled { get; set; }
            public bool EnabledByDefault { get; set; }
        }

        private class PrivilegeCheckResult
        {
            public bool QuerySucceeded { get; set; }
            public bool HasAllRequired { get; set; }
            public List<string> MissingPrivileges { get; } = new List<string>();
            public List<string> DisabledPrivileges { get; } = new List<string>();
            public List<string> Diagnostics { get; } = new List<string>();
            public IReadOnlyList<string> RequiredPrivileges { get; set; } = Array.Empty<string>();
        }

        /// <summary>
        /// Result class for PowerShell execution attempts
        /// </summary>
        private class PowerShellExecutionResult
        {
            public bool Success { get; set; }
            public Collection<PSObject> Results { get; set; } = new Collection<PSObject>();
            public int ExitCode { get; set; }
            public string ErrorMessage { get; set; }
            public string ExitCodeDescription { get; set; }
            public string StandardOutput { get; set; }
            public string StandardError { get; set; }
        }

        private static string EscapeForTrace(string value)
        {
            return string.IsNullOrEmpty(value) ? value : value.Replace("{", "{{").Replace("}", "}}");
        }

        private static string BuildExitCodeDescription(int exitCode, string stderr, string stdout)
        {
            uint unsignedCode = unchecked((uint)exitCode);
            string hexCode = $"0x{unsignedCode:X8}";
            string knownName = GetKnownStatusName(unsignedCode);
            string message = TryGetMessageForExitCode(unsignedCode);

            var sb = new StringBuilder();
            sb.Append(exitCode);
            sb.Append(" (");
            sb.Append(hexCode);
            if (!string.IsNullOrEmpty(knownName))
            {
                sb.Append(", ");
                sb.Append(knownName);
            }
            if (!string.IsNullOrEmpty(message))
            {
                sb.Append(", ");
                sb.Append(message);
            }
            sb.Append(')');

            string stderrSummary = SummarizeStream(stderr, "stderr");
            if (!string.IsNullOrEmpty(stderrSummary))
            {
                sb.Append("; ");
                sb.Append(stderrSummary);
            }

            string stdoutSummary = SummarizeStream(stdout, "stdout");
            if (!string.IsNullOrEmpty(stdoutSummary))
            {
                sb.Append("; ");
                sb.Append(stdoutSummary);
            }

            return sb.ToString();
        }

        /// <summary>
        /// Builds a detailed exception message from PowerShell 7 out-of-process execution errors
        /// This method converts PowerShell script errors to proper exception messages for marshalling
        /// </summary>
        private static string BuildPowerShell7ExceptionMessage(int exitCode, string stderr, string stdout)
        {
            // Start with basic error information
            var sb = new StringBuilder();
            sb.AppendLine("PowerShell 7 script execution failed:");
            
            // Parse stderr for PowerShell exception information
            if (!string.IsNullOrEmpty(stderr))
            {
                string[] stderrLines = stderr.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                
                string exceptionType = null;
                string exceptionMessage = null;
                string scriptLocation = null;
                string stackTrace = null;
                
                foreach (string line in stderrLines)
                {
                    string trimmedLine = line.Trim();
                    
                    // Look for PowerShell exception patterns
                    if (trimmedLine.Contains("Exception calling") || trimmedLine.Contains("Exception:"))
                    {
                        exceptionMessage = trimmedLine;
                    }
                    else if (trimmedLine.Contains("At line:") || trimmedLine.Contains("At "))
                    {
                        scriptLocation = trimmedLine;
                    }
                    else if (trimmedLine.Contains("CategoryInfo") && trimmedLine.Contains("FullyQualifiedErrorId"))
                    {
                        // Extract exception type from CategoryInfo if available
                        var categoryMatch = System.Text.RegularExpressions.Regex.Match(trimmedLine, @"CategoryInfo\s*:\s*\w+:\s*\(\s*[^)]*\)\s*\[\s*([^,\]]+)");
                        if (categoryMatch.Success)
                        {
                            exceptionType = categoryMatch.Groups[1].Value;
                        }
                    }
                    else if (trimmedLine.Contains("FullyQualifiedErrorId"))
                    {
                        // Additional error identification
                        stackTrace = trimmedLine;
                    }
                    else if (trimmedLine.Contains("RuntimeException") || trimmedLine.Contains("TerminatingErrorException"))
                    {
                        exceptionType = trimmedLine;
                    }
                }
                
                // Build comprehensive error message
                if (!string.IsNullOrEmpty(exceptionMessage))
                {
                    sb.AppendLine($"Error: {exceptionMessage}");
                }
                else
                {
                    // Fallback to first non-empty stderr line
                    string firstError = stderrLines.FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));
                    if (!string.IsNullOrEmpty(firstError))
                    {
                        sb.AppendLine($"Error: {firstError.Trim()}");
                    }
                }
                
                if (!string.IsNullOrEmpty(exceptionType))
                {
                    sb.AppendLine($"Exception Type: {exceptionType}");
                }
                
                if (!string.IsNullOrEmpty(scriptLocation))
                {
                    sb.AppendLine($"Location: {scriptLocation}");
                }
                
                if (!string.IsNullOrEmpty(stackTrace))
                {
                    sb.AppendLine($"Stack Trace: {stackTrace}");
                }
            }
            
            // Add exit code information
            uint unsignedCode = unchecked((uint)exitCode);
            string hexCode = $"0x{unsignedCode:X8}";
            string knownName = GetKnownStatusName(unsignedCode);
            
            sb.AppendLine($"Exit Code: {exitCode} ({hexCode})");
            if (!string.IsNullOrEmpty(knownName))
            {
                sb.AppendLine($"Status: {knownName}");
            }
            
            // Add stdout information if it contains error context
            if (!string.IsNullOrEmpty(stdout))
            {
                // Check if stdout contains error information
                if (stdout.ToLowerInvariant().Contains("error") || 
                    stdout.ToLowerInvariant().Contains("exception") ||
                    stdout.ToLowerInvariant().Contains("failed"))
                {
                    string[] stdoutLines = stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    var errorLines = stdoutLines.Where(l => 
                        l.ToLowerInvariant().Contains("error") || 
                        l.ToLowerInvariant().Contains("exception") ||
                        l.ToLowerInvariant().Contains("failed")).Take(3);
                    
                    if (errorLines.Any())
                    {
                        sb.AppendLine("Additional Output:");
                        foreach (string errorLine in errorLines)
                        {
                            sb.AppendLine($"  {errorLine.Trim()}");
                        }
                    }
                }
            }
            
            return sb.ToString().TrimEnd();
        }

        private static string SummarizeStream(string content, string label)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                return null;
            }

            string sanitized = content.Replace("\r", "\\r").Replace("\n", "\\n");
            const int maxLength = 512;
            if (sanitized.Length > maxLength)
            {
                sanitized = sanitized.Substring(0, maxLength) + "...";
            }

            return $"{label}: {sanitized}";
        }

        private static string GetKnownStatusName(uint code)
        {
            switch (code)
            {
                case 0xC0000142:
                    return "STATUS_DLL_INIT_FAILED";
                case 0xC0000135:
                    return "STATUS_DLL_NOT_FOUND";
                case 0xC0000005:
                    return "STATUS_ACCESS_VIOLATION";
                case 0xC0000008:
                    return "STATUS_INVALID_HANDLE";
                case 0xC0000017:
                    return "STATUS_NO_MEMORY";
                case 0xC0000022:
                    return "STATUS_ACCESS_DENIED";
                case 0:
                    return "STATUS_SUCCESS";
                default:
                    return null;
            }
        }

        private static string TryGetMessageForExitCode(uint code)
        {
            const int bufferSize = 512;
            var buffer = new StringBuilder(bufferSize);

            int length = FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                IntPtr.Zero,
                code,
                0,
                buffer,
                buffer.Capacity,
                IntPtr.Zero);

            if (length > 0)
            {
                return buffer.ToString().Trim();
            }

            IntPtr ntdllHandle = IntPtr.Zero;
            try
            {
                ntdllHandle = LoadLibraryEx("ntdll.dll", IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE);
                if (ntdllHandle != IntPtr.Zero)
                {
                    buffer.Clear();
                    length = FormatMessage(
                        FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
                        ntdllHandle,
                        code,
                        0,
                        buffer,
                        buffer.Capacity,
                        IntPtr.Zero);

                    if (length > 0)
                    {
                        return buffer.ToString().Trim();
                    }
                }
            }
            catch
            {
                // Ignored - we best-effort the descriptive message
            }
            finally
            {
                if (ntdllHandle != IntPtr.Zero)
                {
                    FreeLibrary(ntdllHandle);
                }
            }

            return null;
        }

        /// <summary>
        /// Execute PowerShell 7 using ProcessStartInfo approach
        /// </summary>
        private PowerShellExecutionResult ExecuteWithProcessStartInfo(Process process, string stdinContent)
        {
            var result = new PowerShellExecutionResult();
            
            try
            {
                Tracer.TraceInformation("attempting-powershell7-execution-with-stdin-processstartinfo");
                process.Start();

                // Write the stdin content to the process
                using (var stdin = process.StandardInput)
                {
                    stdin.Write(stdinContent);
                }

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();
                
                result.ExitCode = process.ExitCode;
                result.StandardOutput = output;
                result.StandardError = error;
                result.ExitCodeDescription = BuildExitCodeDescription(process.ExitCode, error, output);
                
                // Debug output to understand what's happening
                Tracer.TraceInformation("powershell7-process-exit-code: {0}", process.ExitCode);
                Tracer.TraceInformation("powershell7-stdout-length: {0}", output?.Length ?? 0);
                Tracer.TraceInformation("powershell7-stderr-length: {0}", error?.Length ?? 0);
                if (!string.IsNullOrEmpty(error))
                {
                    Tracer.TraceWarning("powershell7-stderr-content: {0}", 0, error);
                }
                if (!string.IsNullOrEmpty(output))
                {
                    Tracer.TraceInformation("powershell7-stdout-preview: {0}", output.Length > 500 ? output.Substring(0, 500) + "..." : output);
                }
                
                if (process.ExitCode == 0)
                {
                    result.Success = true;
                    
                    // Process output as PowerShell objects and capture variables
                    if (!string.IsNullOrEmpty(output))
                    {
                        string[] outputLines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                        bool inVariableCapture = false;
                        bool inObjectCapture = false;
                        var objectJsonBuilder = new StringBuilder();
                        
                        foreach (string line in outputLines)
                        {
                            string trimmedLine = line.Trim();
                            if (string.IsNullOrWhiteSpace(trimmedLine)) continue;
                            
                            // Check for variable capture markers
                            if (trimmedLine == "PSMA_VAR_START")
                            {
                                inVariableCapture = true;
                                Tracer.TraceInformation("powershell7-variable-capture-started");
                                continue;
                            }
                            else if (trimmedLine == "PSMA_VAR_END")
                            {
                                inVariableCapture = false;
                                Tracer.TraceInformation("powershell7-variable-capture-completed");
                                continue;
                            }
                            
                            // Check for object capture markers
                            if (trimmedLine == "PSMA_OBJECT_START")
                            {
                                inObjectCapture = true;
                                objectJsonBuilder.Clear();
                                continue;
                            }
                            else if (trimmedLine == "PSMA_OBJECT_END")
                            {
                                inObjectCapture = false;
                                // Parse key=value pairs back to hashtable
                                string keyValuePairs = objectJsonBuilder.ToString();
                                if (!string.IsNullOrEmpty(keyValuePairs))
                                {
                                    try
                                    {
                                        // Create actual Hashtable as base object to match MA.Import.cs expectations
                                        Hashtable hashTable = new Hashtable(StringComparer.OrdinalIgnoreCase);
                                        var lines = keyValuePairs.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                                        int propertyCount = 0;
                                        
                                        foreach (var kvLine in lines)
                                        {
                                            var trimmedKvLine = kvLine.Trim();
                                            var pipeIndex = trimmedKvLine.IndexOf('|');
                                            if (pipeIndex > 0 && pipeIndex < trimmedKvLine.Length - 1)
                                            {
                                                var propertyType = trimmedKvLine.Substring(0, pipeIndex);
                                                var keyvalue = trimmedKvLine.Substring(pipeIndex + 1);

                                                var equalIndex = keyvalue.IndexOf('=');
                                                if (equalIndex > 0)
                                                {
                                                    string key = keyvalue.Substring(0, equalIndex);
                                                    string value = null;
                                                    if (equalIndex < keyvalue.Length - 1)
                                                    {
                                                        value = keyvalue.Substring(equalIndex + 1);
                                                    }

                                                    hashTable[key] = ConvertFromJSONString(value, propertyType);
                                                    propertyCount++;
                                                }
                                            }
                                        }
                                        
                                        // Special handling for _ObjectValue fallback case
                                        if (propertyCount == 1 && hashTable.ContainsKey("_ObjectValue"))
                                        {
                                            // This was a simple object that couldn't be decomposed - use its string value directly
                                            PSObject simpleObject = new PSObject(hashTable["_ObjectValue"]);
                                            result.Results.Add(simpleObject);
                                            Tracer.TraceInformation("powershell7-parsed-simple-object: '{0}'", EscapeForTrace(hashTable["_ObjectValue"].ToString()));
                                        }
                                        else
                                        {
                                            // Wrap Hashtable in PSObject to maintain consistency with PowerShell output
                                            PSObject psObject = new PSObject(hashTable);
                                            result.Results.Add(psObject);
                                            Tracer.TraceInformation("powershell7-parsed-hashtable-object: {0} properties", propertyCount);
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        Tracer.TraceError("powershell7-keyvalue-parse-error", ex);
                                        // Fallback: treat as regular string
                                        PSObject fallbackObject = new PSObject(keyValuePairs);
                                        result.Results.Add(fallbackObject);
                                    }
                                }
                                continue;
                            }
                            
                            if (inVariableCapture)
                            {
                                // Parse variable: "VariableName=Value"
                                var equalIndex = trimmedLine.IndexOf('=');
                                if (equalIndex > 0 && equalIndex < trimmedLine.Length - 1)
                                {
                                    string varName = trimmedLine.Substring(0, equalIndex);
                                    string varValue = trimmedLine.Substring(equalIndex + 1);
                                    
                                    // Convert string values to appropriate types
                                    object convertedValue = varValue;
                                    if (bool.TryParse(varValue, out bool boolValue))
                                    {
                                        convertedValue = boolValue;
                                    }
                                    
                                    sessionVariables[varName] = convertedValue;
                                    Tracer.TraceInformation("powershell7-captured-variable: {0} = {1}", varName, varValue);
                                }
                            }
                            else if (inObjectCapture)
                            {
                                // Accumulate JSON content
                                objectJsonBuilder.AppendLine(trimmedLine);
                            }
                            else
                            {
                                // Unexpected output line outside of structured markers - log for debugging
                                Tracer.TraceWarning("powershell7-unexpected-output-line: '{0}'", 1, EscapeForTrace(trimmedLine));
                            }
                        }
                    }
                    
                    Tracer.TraceInformation("*** POWERSHELL 7 OBJECT PROCESSING SUMMARY ***");
                    Tracer.TraceInformation("powershell7-objects-successfully-parsed: {0}", result.Results.Count);
                    Tracer.TraceInformation("*** END POWERSHELL 7 OBJECT PROCESSING SUMMARY ***");
                }
                else
                {
                    result.Success = false;
                    result.ErrorMessage = result.ExitCodeDescription;
                    Tracer.TraceError("processstartinfo-execution-failed exit-code-detail: {0}", 0, EscapeForTrace(result.ExitCodeDescription));
                    
                    // FIX: Convert PowerShell 7 script errors to exceptions for proper marshalling
                    // This ensures compatibility with ECMA/MIM engine exception handling expectations
                    string exceptionMessage = BuildPowerShell7ExceptionMessage(process.ExitCode, error, output);
                    Tracer.TraceError("powershell7-script-exception-detected: {0}", 0, EscapeForTrace(exceptionMessage));
                    
                    // Throw a RuntimeException to match Windows PowerShell 5.1 behavior
                    // This allows the ECMA/MIM engine to properly catch and handle script errors
                    throw new System.Management.Automation.RuntimeException(exceptionMessage);
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ExitCode = -1;
                result.ErrorMessage = ex.Message;
                result.ExitCodeDescription = ex.Message;
                Tracer.TraceError("processstartinfo-execution-exception", ex);
            }
            
            return result;
        }

        private PowerShellExecutionResult ExecuteWithCreateProcessWithTokenAndCompatibility(
            string username, 
            string domain, 
            string password,
            string applicationPath, 
            string arguments, 
            string workingDirectory,
            Dictionary<string, string> inheritedEnvironment)
        {
            // First attempt: Normal PowerShell 7 launch with profile
            Tracer.TraceInformation("attempting-token-launch-normal-mode");
            var result = ExecuteWithCreateProcessWithToken(username, domain, password, applicationPath, arguments, workingDirectory, inheritedEnvironment, LOGON_WITH_PROFILE, CREATE_UNICODE_ENVIRONMENT_FLAG | CREATE_NO_WINDOW_FLAG, true);
            
            // Check if PowerShell 7 crashed with DLL initialization failure
            if (!result.Success && result.ExitCode == -1073741502) // STATUS_DLL_INIT_FAILED
            {
                Tracer.TraceWarning("token-launch-normal-mode-dll-init-failed attempting-service-compatibility-mode");
                
                // Second attempt: Service compatibility mode without profile loading
                result = ExecuteWithCreateProcessWithToken(username, domain, password, applicationPath, arguments, workingDirectory, inheritedEnvironment, LOGON_NETCREDENTIALS_ONLY, CREATE_UNICODE_ENVIRONMENT_FLAG | CREATE_NO_WINDOW_FLAG, true);
                
                if (!result.Success && result.ExitCode == -1073741502)
                {
                    Tracer.TraceWarning("token-launch-service-compatibility-mode-dll-init-failed attempting-minimal-environment-mode");
                    
                    // Third attempt: Minimal environment mode
                    result = ExecuteWithCreateProcessWithToken(username, domain, password, applicationPath, arguments, workingDirectory, null, LOGON_NETCREDENTIALS_ONLY, CREATE_UNICODE_ENVIRONMENT_FLAG | CREATE_NO_WINDOW_FLAG, false);
                    
                    if (!result.Success && result.ExitCode == -1073741502)
                    {
                        Tracer.TraceWarning("token-launch-minimal-environment-mode-dll-init-failed attempting-no-inheritance-mode");
                        
                        // Fourth attempt: No environment inheritance
                        result = ExecuteWithCreateProcessWithToken(username, domain, password, applicationPath, arguments, workingDirectory, null, LOGON_NETCREDENTIALS_ONLY, CREATE_NO_WINDOW_FLAG, false);
                        
                        if (!result.Success && result.ExitCode == -1073741502)
                        {
                            Tracer.TraceError("token-launch-all-compatibility-modes-failed-with-dll-init-failure");
                        }
                        else if (result.Success)
                        {
                            Tracer.TraceInformation("token-launch-no-inheritance-mode-success");
                        }
                    }
                    else if (result.Success)
                    {
                        Tracer.TraceInformation("token-launch-minimal-environment-mode-success");
                    }
                }
                else if (result.Success)
                {
                    Tracer.TraceInformation("token-launch-service-compatibility-mode-success");
                }
            }
            else if (result.Success)
            {
                Tracer.TraceInformation("token-launch-normal-mode-success");
            }
            
            return result;
        }

        private PowerShellExecutionResult ExecuteWithCreateProcessWithToken(
            string username,
            string domain,
            string password,
            string applicationPath,
            string arguments,
            string workingDirectory,
            Dictionary<string, string> environment,
            uint logonFlags = LOGON_WITH_PROFILE,
            uint creationFlags = CREATE_UNICODE_ENVIRONMENT_FLAG | CREATE_NO_WINDOW_FLAG,
            bool useEnvironment = true)
        {
            var result = new PowerShellExecutionResult();

            SafeAccessTokenHandle logonHandle = null;
            IntPtr primaryToken = IntPtr.Zero;
            IntPtr userEnvBlock = IntPtr.Zero;
            IntPtr mergedEnvBlock = IntPtr.Zero;
            IntPtr stdOutRead = IntPtr.Zero;
            IntPtr stdOutWrite = IntPtr.Zero;
            IntPtr stdErrRead = IntPtr.Zero;
            IntPtr stdErrWrite = IntPtr.Zero;
            IntPtr commandLinePtr = IntPtr.Zero;
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            PROFILEINFO profileInfo = new PROFILEINFO();
            bool profileLoaded = false;
            Task<string> stdoutTask = null;
            Task<string> stderrTask = null;
            PrivilegeCheckResult privilegeCheck = null;

            try
            {
                Tracer.TraceInformation("token-launch-start username:'{0}', domain:'{1}'", username, domain ?? "");

                privilegeCheck = EvaluateCallerPrivilegeRequirements();
                if (privilegeCheck.Diagnostics.Count > 0)
                {
                    foreach (var diagnostic in privilegeCheck.Diagnostics)
                    {
                        Tracer.TraceInformation("token-launch-privilege-diagnostic: {0}", diagnostic);
                    }
                }

                if (!privilegeCheck.QuerySucceeded)
                {
                    Tracer.TraceWarning("token-launch-privilege-enumeration-warning: {0}", 0, privilegeCheck.Diagnostics.LastOrDefault() ?? "Unable to enumerate caller privileges automatically.");
                }
                else if (!privilegeCheck.HasAllRequired)
                {
                    // If we have disabled (but present) privileges, try to enable them automatically
                    if (privilegeCheck.DisabledPrivileges.Any() && privilegeCheck.MissingPrivileges.Count == 0)
                    {
                        Tracer.TraceWarning("token-launch-detected-disabled-privileges-attempting-enablement: {0}", 0, string.Join(", ", privilegeCheck.DisabledPrivileges));
                        
                        if (TryEnableRequiredPrivileges(out string enableError))
                        {
                            // Re-check privileges after enablement attempt
                            var recheck = EvaluateCallerPrivilegeRequirements();
                            if (recheck.HasAllRequired)
                            {
                                Tracer.TraceInformation("token-launch-privilege-enablement-successful-proceeding");
                            }
                            else
                            {
                                string guidance = BuildPrivilegeGuidanceMessage("PowerShell 7 impersonation cannot continue. Some privileges were enabled, but required privileges are still missing or disabled.", recheck);
                                result.Success = false;
                                result.ExitCode = -1;
                                result.ErrorMessage = guidance;
                                result.ExitCodeDescription = guidance;
                                Tracer.TraceError("token-launch-partial-privilege-enablement-insufficient: {0}", EscapeForTrace(guidance));
                                return result;
                            }
                        }
                        else
                        {
                            string guidance = BuildPrivilegeGuidanceMessage($"PowerShell 7 impersonation cannot continue. Privilege enablement failed: {enableError ?? "Unknown error"}", privilegeCheck);
                            result.Success = false;
                            result.ExitCode = -1;
                            result.ErrorMessage = guidance;
                            result.ExitCodeDescription = guidance;
                            Tracer.TraceError("token-launch-privilege-enablement-failed: {0}", EscapeForTrace(guidance));
                            return result;
                        }
                    }
                    else
                    {
                        string guidance = BuildPrivilegeGuidanceMessage("PowerShell 7 impersonation cannot continue because the Synchronization Service account is missing required user rights.", privilegeCheck);
                        result.Success = false;
                        result.ExitCode = -1;
                        result.ErrorMessage = guidance;
                        result.ExitCodeDescription = guidance;
                        Tracer.TraceError("token-launch-missing-required-privileges: {0}", EscapeForTrace(guidance));
                        return result;
                    }
                }

                if (!TryAcquireUserToken(username, domain, password, out logonHandle, out string logonError))
                {
                    result.Success = false;
                    result.ExitCode = -1;
                    result.ErrorMessage = logonError;
                    result.ExitCodeDescription = logonError;
                    Tracer.TraceError("token-launch-logon-failed: {0}", logonError);
                    return result;
                }

                if (!DuplicateTokenEx(logonHandle.DangerousGetHandle(), TOKEN_ACCESS_FLAGS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out primaryToken))
                {
                    int duplicateError = Marshal.GetLastWin32Error();
                    string errorDescription = FormatWin32ErrorMessage(duplicateError);
                    result.Success = false;
                    result.ExitCode = -1;
                    result.ErrorMessage = $"DuplicateTokenEx failed: {errorDescription}";
                    result.ExitCodeDescription = result.ErrorMessage;
                    Tracer.TraceError("token-launch-duplicate-token-failed: {0}", result.ErrorMessage);
                    return result;
                }

                profileInfo.dwSize = Marshal.SizeOf(typeof(PROFILEINFO));
                profileInfo.lpUserName = username;

                if (LoadUserProfile(primaryToken, ref profileInfo))
                {
                    profileLoaded = true;
                    Tracer.TraceInformation("token-launch-loaded-profile path:'{0}'", profileInfo.lpProfilePath ?? "");
                }
                else
                {
                    int profileError = Marshal.GetLastWin32Error();
                    Tracer.TraceWarning("token-launch-load-profile-failed error:{0} detail:{1}", 0, profileError, FormatWin32ErrorMessage(profileError));

                    if (profileError == ERROR_PRIVILEGE_NOT_HELD || profileError == ERROR_ACCESS_DENIED)
                    {
                        string guidance = BuildPrivilegeGuidanceMessage("LoadUserProfile could not initialize the impersonated user profile because the caller lacks required rights.", privilegeCheck, profileError, "LoadUserProfile");
                        result.Success = false;
                        result.ExitCode = -1;
                        result.ErrorMessage = guidance;
                        result.ExitCodeDescription = guidance;
                        Tracer.TraceError("token-launch-load-profile-privilege-error: {0}", EscapeForTrace(guidance));
                        return result;
                    }
                }

                var runtimeEnvironment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                if (CreateEnvironmentBlock(out userEnvBlock, primaryToken, false))
                {
                    var userEnvironment = ConvertEnvironmentBlockToDictionary(userEnvBlock);
                    foreach (var kvp in userEnvironment)
                    {
                        runtimeEnvironment[kvp.Key] = kvp.Value;
                    }
                    Tracer.TraceInformation("token-launch-loaded-user-environment variables:{0}", runtimeEnvironment.Count);
                }
                else
                {
                    int envError = Marshal.GetLastWin32Error();
                    Tracer.TraceWarning("token-launch-create-environment-block-failed error:{0} detail:{1}", 0, envError, FormatWin32ErrorMessage(envError));
                }

                if (environment != null)
                {
                    foreach (var kvp in environment)
                    {
                        runtimeEnvironment[kvp.Key] = kvp.Value ?? string.Empty;
                    }
                }

                mergedEnvBlock = BuildEnvironmentBlockPointer(runtimeEnvironment);

                var securityAttributes = new SECURITY_ATTRIBUTES
                {
                    nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
                    bInheritHandle = true,
                    lpSecurityDescriptor = IntPtr.Zero
                };

                if (!CreatePipe(out stdOutRead, out stdOutWrite, ref securityAttributes, 0))
                {
                    int pipeError = Marshal.GetLastWin32Error();
                    throw new InvalidOperationException($"Failed to create stdout pipe: {FormatWin32ErrorMessage(pipeError)}");
                }

                if (!SetHandleInformation(stdOutRead, HANDLE_FLAG_INHERIT, 0))
                {
                    int handleError = Marshal.GetLastWin32Error();
                    throw new InvalidOperationException($"Failed to set stdout handle information: {FormatWin32ErrorMessage(handleError)}");
                }

                if (!CreatePipe(out stdErrRead, out stdErrWrite, ref securityAttributes, 0))
                {
                    int pipeError = Marshal.GetLastWin32Error();
                    throw new InvalidOperationException($"Failed to create stderr pipe: {FormatWin32ErrorMessage(pipeError)}");
                }

                if (!SetHandleInformation(stdErrRead, HANDLE_FLAG_INHERIT, 0))
                {
                    int handleError = Marshal.GetLastWin32Error();
                    throw new InvalidOperationException($"Failed to set stderr handle information: {FormatWin32ErrorMessage(handleError)}");
                }

                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                    dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES,
                    wShowWindow = SW_HIDE,
                    hStdOutput = stdOutWrite,
                    hStdError = stdErrWrite,
                    hStdInput = IntPtr.Zero
                };

                string commandLine = $"\"{applicationPath}\" {(arguments ?? string.Empty)}".Trim();
                commandLinePtr = Marshal.StringToHGlobalUni(commandLine);

                Tracer.TraceInformation("token-launch-createprocess command:'{0}'", commandLine);

                // Use parameterized CreateProcessWithTokenW call
                IntPtr envBlockToUse = useEnvironment ? mergedEnvBlock : IntPtr.Zero;
                bool processCreated = CreateProcessWithTokenW(primaryToken, logonFlags, applicationPath, commandLinePtr, creationFlags, envBlockToUse, workingDirectory, ref startupInfo, out processInfo);
                
                if (!processCreated)
                {
                    int createError = Marshal.GetLastWin32Error();
                    string message;

                    if (createError == ERROR_PRIVILEGE_NOT_HELD || createError == ERROR_ACCESS_DENIED)
                    {
                        message = BuildPrivilegeGuidanceMessage("CreateProcessWithTokenW refused to launch the PowerShell 7 host because the Synchronization Service account is missing required rights.", privilegeCheck, createError, "CreateProcessWithTokenW");
                    }
                    else
                    {
                        message = $"CreateProcessWithTokenW failed: {FormatWin32ErrorMessage(createError)}";
                    }

                    result.Success = false;
                    result.ExitCode = -1;
                    result.ErrorMessage = message;
                    result.ExitCodeDescription = message;
                    Tracer.TraceError("token-launch-createprocess-failed: {0}", EscapeForTrace(message));
                    return result;
                }

                CloseHandleSafe(processInfo.hThread);
                processInfo.hThread = IntPtr.Zero;

                CloseHandleSafe(stdOutWrite);
                stdOutWrite = IntPtr.Zero;
                CloseHandleSafe(stdErrWrite);
                stdErrWrite = IntPtr.Zero;

                var stdoutHandle = stdOutRead;
                stdOutRead = IntPtr.Zero;
                var stderrHandle = stdErrRead;
                stdErrRead = IntPtr.Zero;

                stdoutTask = Task.Run(() => ReadPipeToEnd(stdoutHandle));
                stderrTask = Task.Run(() => ReadPipeToEnd(stderrHandle));

                uint waitResult = WaitForSingleObject(processInfo.hProcess, INFINITE);
                if (waitResult == WAIT_FAILED)
                {
                    int waitError = Marshal.GetLastWin32Error();
                    Tracer.TraceWarning("token-launch-wait-failed error:{0} detail:{1}", 0, waitError, FormatWin32ErrorMessage(waitError));
                }

                string stdout = stdoutTask.Result;
                string stderr = stderrTask.Result;

                if (!GetExitCodeProcess(processInfo.hProcess, out uint exitCode))
                {
                    int exitError = Marshal.GetLastWin32Error();
                    Tracer.TraceWarning("token-launch-get-exit-code-failed error:{0} detail:{1}", 0, exitError, FormatWin32ErrorMessage(exitError));
                    exitCode = 0xFFFFFFFF;
                }

                CloseHandleSafe(processInfo.hProcess);
                processInfo.hProcess = IntPtr.Zero;

                result.ExitCode = unchecked((int)exitCode);
                result.StandardOutput = stdout;
                result.StandardError = stderr;
                result.ExitCodeDescription = BuildExitCodeDescription(result.ExitCode, stderr, stdout);
                result.Success = exitCode == 0;

                if (result.Success)
                {
                    if (!string.IsNullOrEmpty(stdout))
                    {
                        string[] outputLines = stdout.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var line in outputLines)
                        {
                            result.Results.Add(new PSObject(line.Trim()));
                        }
                    }
                    Tracer.TraceInformation("token-launch-succeeded exit-code:{0}", exitCode);
                }
                else
                {
                    result.ErrorMessage = result.ExitCodeDescription;
                    Tracer.TraceWarning("token-launch-failed exit-code:{0} detail:{1}", 0, exitCode, result.ExitCodeDescription);
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ExitCode = -1;
                result.ErrorMessage = ex.Message;
                result.ExitCodeDescription = ex.Message;
                Tracer.TraceError("token-launch-exception", ex);
            }
            finally
            {
                // Ensure tasks complete and handles released
                try
                {
                    stdoutTask?.Wait(100);
                }
                catch
                {
                    // ignore
                }

                try
                {
                    stderrTask?.Wait(100);
                }
                catch
                {
                    // ignore
                }

                if (stdoutTask == null && stdOutRead != IntPtr.Zero)
                {
                    CloseHandleSafe(stdOutRead);
                    stdOutRead = IntPtr.Zero;
                }

                if (stderrTask == null && stdErrRead != IntPtr.Zero)
                {
                    CloseHandleSafe(stdErrRead);
                    stdErrRead = IntPtr.Zero;
                }

                CloseHandleSafe(stdOutWrite);
                CloseHandleSafe(stdErrWrite);

                if (processInfo.hThread != IntPtr.Zero)
                {
                    CloseHandleSafe(processInfo.hThread);
                    processInfo.hThread = IntPtr.Zero;
                }

                if (processInfo.hProcess != IntPtr.Zero)
                {
                    CloseHandleSafe(processInfo.hProcess);
                    processInfo.hProcess = IntPtr.Zero;
                }

                if (commandLinePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(commandLinePtr);
                    commandLinePtr = IntPtr.Zero;
                }

                if (mergedEnvBlock != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(mergedEnvBlock);
                    mergedEnvBlock = IntPtr.Zero;
                }

                if (userEnvBlock != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(userEnvBlock);
                    userEnvBlock = IntPtr.Zero;
                }

                if (profileLoaded && profileInfo.hProfile != IntPtr.Zero)
                {
                    UnloadUserProfile(primaryToken, profileInfo.hProfile);
                    profileInfo.hProfile = IntPtr.Zero;
                }

                if (primaryToken != IntPtr.Zero)
                {
                    CloseHandleSafe(primaryToken);
                    primaryToken = IntPtr.Zero;
                }

                logonHandle?.Dispose();
            }

            return result;
        }

        private bool TryAcquireUserToken(string username, string domain, string password, out SafeAccessTokenHandle tokenHandle, out string errorMessage)
        {
            tokenHandle = null;
            errorMessage = null;

            IntPtr rawToken;
            if (LogonUser(username, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out rawToken))
            {
                tokenHandle = new SafeAccessTokenHandle(rawToken);
                Tracer.TraceInformation("token-launch-logon-interactive-success");
                return true;
            }

            int error = Marshal.GetLastWin32Error();
            Tracer.TraceWarning("token-launch-logon-interactive-failed error:{0} detail:{1}", 0, error, FormatWin32ErrorMessage(error));

            if (error == ERROR_LOGON_TYPE_NOT_GRANTED)
            {
                if (LogonUser(username, domain, password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, out rawToken))
                {
                    tokenHandle = new SafeAccessTokenHandle(rawToken);
                    Tracer.TraceInformation("token-launch-logon-batch-success");
                    return true;
                }

                error = Marshal.GetLastWin32Error();
                Tracer.TraceWarning("token-launch-logon-batch-failed error:{0} detail:{1}", 0, error, FormatWin32ErrorMessage(error));
            }

            errorMessage = $"LogonUser failed with error {error}: {FormatWin32ErrorMessage(error)}";
            return false;
        }

        private static Dictionary<string, string> ConvertEnvironmentBlockToDictionary(IntPtr environmentBlock)
        {
            var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (environmentBlock == IntPtr.Zero)
            {
                return environment;
            }

            IntPtr current = environmentBlock;
            while (true)
            {
                string entry = Marshal.PtrToStringUni(current);
                if (string.IsNullOrEmpty(entry))
                {
                    break;
                }

                int separatorIndex = entry.IndexOf('=');
                if (separatorIndex > 0)
                {
                    string key = entry.Substring(0, separatorIndex);
                    string value = separatorIndex < entry.Length - 1 ? entry.Substring(separatorIndex + 1) : string.Empty;
                    environment[key] = value;
                }

                current = IntPtr.Add(current, (entry.Length + 1) * sizeof(char));
            }

            return environment;
        }

        private static IntPtr BuildEnvironmentBlockPointer(Dictionary<string, string> environment)
        {
            if (environment == null || environment.Count == 0)
            {
                return IntPtr.Zero;
            }

            var ordered = environment.OrderBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase);
            var builder = new StringBuilder();

            foreach (var kvp in ordered)
            {
                builder.Append(kvp.Key);
                builder.Append('=');
                builder.Append(kvp.Value ?? string.Empty);
                builder.Append('\0');
            }

            builder.Append('\0');

            return Marshal.StringToHGlobalUni(builder.ToString());
        }

        private static string ReadPipeToEnd(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                return string.Empty;
            }

            using (var safeHandle = new SafeFileHandle(handle, ownsHandle: true))
            using (var stream = new FileStream(safeHandle, FileAccess.Read, 4096, false))
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        private static string FormatWin32ErrorMessage(int errorCode)
        {
            const int bufferSize = 512;
            var buffer = new StringBuilder(bufferSize);

            int length = FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                IntPtr.Zero,
                (uint)errorCode,
                0,
                buffer,
                buffer.Capacity,
                IntPtr.Zero);

            if (length > 0)
            {
                return buffer.ToString().Trim();
            }

            return $"Error {errorCode}";
        }

        private static void CloseHandleSafe(IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
            }
        }

        /// <summary>
        /// Execute PowerShell 7 using PowerShell Jobs approach for service context compatibility
        /// </summary>
        private PowerShellExecutionResult ExecuteWithPowerShellJob(string stdinContent, string username, string domain, string password)
        {
            var result = new PowerShellExecutionResult();
            
            try
            {
                Tracer.TraceInformation("attempting-powershell7-execution-with-powershell-job");
                
                // Create PowerShell credential object
                var securePassword = new System.Security.SecureString();
                foreach (char c in password)
                {
                    securePassword.AppendChar(c);
                }
                securePassword.MakeReadOnly();
                
                var credential = new System.Management.Automation.PSCredential($"{domain}\\{username}", securePassword);
                
                // Create PowerShell Job that executes PowerShell 7
                using (var powershell = PowerShell.Create())
                {
                    powershell.AddScript(@"
                        try {
                            $job = Start-Job -ScriptBlock {
                                param($ps7Path, $stdinScript)
                                $stdinScript | & $ps7Path -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -
                            } -ArgumentList 'C:\Program Files\PowerShell\7\pwsh.exe', @'
" + stdinContent + @"
'@ -Credential $using:credential

                            $job | Wait-Job -Timeout 300 | Out-Null
                            
                            if ($job.State -eq 'Completed') {
                                $output = $job | Receive-Job
                                $job | Remove-Job -Force
                                return @{ Success = $true; Output = $output; ExitCode = 0 }
                            } elseif ($job.State -eq 'Failed') {
                                $error = $job.ChildJobs[0].Error | Out-String
                                $job | Remove-Job -Force  
                                return @{ Success = $false; Output = $null; ExitCode = 1; Error = $error }
                            } else {
                                $job | Stop-Job -PassThru | Remove-Job -Force
                                return @{ Success = $false; Output = $null; ExitCode = 2; Error = 'Job timed out or failed to complete' }
                            }
                        } catch {
                            return @{ Success = $false; Output = $null; ExitCode = 3; Error = $_.Exception.Message }
                        }
                    ");
                    
                    var jobResults = powershell.Invoke();
                    
                    if (powershell.Streams.Error.Count > 0)
                    {
                        var errors = string.Join("; ", powershell.Streams.Error.Select(e => e.ToString()));
                        result.Success = false;
                        result.ErrorMessage = $"PowerShell Job errors: {errors}";
                        Tracer.TraceError($"powershell-job-execution-errors: {errors}");
                    }
                    else if (jobResults.Count > 0)
                    {
                        var jobResult = jobResults[0];
                        var successProperty = jobResult.Properties["Success"];
                        var outputProperty = jobResult.Properties["Output"];
                        var exitCodeProperty = jobResult.Properties["ExitCode"];
                        var errorProperty = jobResult.Properties["Error"];
                        
                        if (successProperty?.Value is bool success && success)
                        {
                            result.Success = true;
                            result.ExitCode = 0;
                            
                            if (outputProperty?.Value != null)
                            {
                                // Convert output to PSObject collection
                                var output = outputProperty.Value.ToString();
                                if (!string.IsNullOrEmpty(output))
                                {
                                    string[] outputLines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                                    
                                    foreach (string line in outputLines)
                                    {
                                        if (!string.IsNullOrWhiteSpace(line))
                                        {
                                            PSObject psObject = new PSObject(line.Trim());
                                            result.Results.Add(psObject);
                                        }
                                    }
                                }
                                result.StandardOutput = outputProperty.Value.ToString();
                            }
                            result.ExitCodeDescription = BuildExitCodeDescription(0, null, result.StandardOutput);
                            
                            Tracer.TraceInformation("powershell-job-execution-successful-objects-returned: {0}", result.Results.Count);
                        }
                        else
                        {
                            result.Success = false;
                            result.ExitCode = exitCodeProperty?.Value as int? ?? -1;
                            result.ErrorMessage = errorProperty?.Value?.ToString() ?? "Unknown job execution error";
                            result.ExitCodeDescription = result.ErrorMessage;
                            Tracer.TraceError($"powershell-job-execution-failed: {result.ErrorMessage}");
                        }
                    }
                    else
                    {
                        result.Success = false;
                        result.ExitCode = -1;
                        result.ErrorMessage = "No results returned from PowerShell job";
                        result.ExitCodeDescription = result.ErrorMessage;
                        Tracer.TraceError("powershell-job-no-results-returned");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ExitCode = -1;
                result.ErrorMessage = ex.Message;
                result.ExitCodeDescription = ex.Message;
                Tracer.TraceError($"powershell-job-execution-exception: {ex.Message}");
            }
            
            return result;
        }

        private string EscapeParameterValue(object value)
        {
            if (value == null)
                return "$null";
            
            // Handle common .NET types properly
            if (value is string str)
            {
                if (string.IsNullOrEmpty(str))
                    return "\"\"";
                    
                // Always quote string values to prevent them from being interpreted as commands
                // Escape internal quotes and wrap in quotes
                return $"'{str.Replace("'", "''")}'";
            }
            
            if (value is bool boolean)
                return boolean ? "$true" : "$false";
                
            if (value is int || value is long || value is double || value is decimal || value is float)
                return value.ToString();
            
            // Check for hashtables and collections BEFORE PSObject to handle them correctly
            if (value is System.Collections.IDictionary hashtable)
            {
                Tracer.TraceInformation("hashtable-serialization: converting IDictionary with {0} entries", hashtable.Count);
                var items = new List<string>();
                foreach (System.Collections.DictionaryEntry entry in hashtable)
                {
                    string escapedValue = EscapeParameterValue(entry.Value);
                    Tracer.TraceInformation("hashtable-entry-debug: key='{0}', value-type='{1}', value='{2}', escaped='{3}'", 
                        entry.Key ?? "(null)", 
                        entry.Value?.GetType().Name ?? "(null)", 
                        entry.Value ?? "(null)", 
                        escapedValue ?? "(null)");
                        
                    // Ensure we never generate malformed hashtable syntax like "key="
                    if (string.IsNullOrEmpty(escapedValue) || escapedValue.Trim() == "")
                    {
                        escapedValue = "\"\"";  // Always use empty string for any empty/null values
                        Tracer.TraceInformation("hashtable-fixed-empty-value: key='{0}', fixed-to='{1}'", entry.Key, escapedValue);
                    }
                    
                    // FIX: Properly escape hashtable keys that contain special PowerShell characters
                    string keyName = EscapePropertyName(entry.Key?.ToString() ?? "null");
                    items.Add(keyName + " = " + escapedValue);
                }
                return "@{" + string.Join("; ", items) + "}";
            }
            
            // Handle PSObject specifically 
            if (value is PSObject psObject)
            {
                Tracer.TraceInformation("psobject-serialization: converting PSObject with {0} properties", psObject.Properties.Count());
                
                var items = new List<string>();
                foreach (var property in psObject.Properties)
                {
                    try
                    {
                        string escapedValue = EscapeParameterValue(property.Value);
                        Tracer.TraceInformation("psobject-property-debug: name='{0}', value-type='{1}', value='{2}', escaped='{3}'", 
                            property.Name ?? "(null)", 
                            property.Value?.GetType().Name ?? "(null)", 
                            property.Value ?? "(null)", 
                            escapedValue ?? "(null)");
                            
                        // Ensure we never generate malformed hashtable syntax like "key="
                        if (string.IsNullOrEmpty(escapedValue) || escapedValue.Trim() == "")
                        {
                            escapedValue = "\"\"";  // Always use empty string for any empty/null values
                            Tracer.TraceInformation("psobject-fixed-empty-value: name='{0}', fixed-to='{1}'", property.Name, escapedValue);
                        }
                        
                        // FIX: Properly escape property names that contain special PowerShell characters
                        string propertyName = EscapePropertyName(property.Name);
                        items.Add(propertyName + " = " + escapedValue);  // Use space around = for better readability
                    }
                    catch (Exception ex)
                    {
                        Tracer.TraceWarning("psobject-property-error: name='{0}', error='{1}'", 0, property.Name, ex.Message);
                        string safePropertyName = EscapePropertyName(property.Name);
                        items.Add(safePropertyName + " = \"\"");  // Fallback to empty string for problematic properties
                    }
                }
                
                // Create a PSCustomObject from the hashtable to maintain object type
                return "[PSCustomObject]@{ " + string.Join("; ", items) + " }";
            }
            
            if (value is System.Collections.IEnumerable enumerable && !(value is string))
            {
                var items = new List<string>();
                foreach (var item in enumerable)
                {
                    items.Add(EscapeParameterValue(item));
                }
                return $"@({string.Join(", ", items)})";
            }
            
            // For complex .NET objects, create a simplified representation or skip them
            string stringValue = value.ToString();
            Tracer.TraceWarning("complex-object-parameter: {0} = {1}", 0, value.GetType().Name, stringValue);
            
            // Handle Microsoft.MetadirectoryServices objects specially - these are complex objects that should be simplified
            if (value.GetType().FullName.StartsWith("Microsoft.MetadirectoryServices."))
            {
                Tracer.TraceInformation("simplifying-metadirectoryservices-object: {0}", value.GetType().Name);
                
                // For SchemaAttribute objects, create a simple representation with just the name and type
                if (value.GetType().Name == "SchemaAttribute")
                {
                    try
                    {
                        // Use reflection to get Name and DataType properties
                        var nameProperty = value.GetType().GetProperty("Name");
                        var dataTypeProperty = value.GetType().GetProperty("DataType");
                        var isMultiValuedProperty = value.GetType().GetProperty("IsMultiValued");
                        var isAnchorProperty = value.GetType().GetProperty("IsAnchor");
                        
                        string name = nameProperty?.GetValue(value)?.ToString() ?? "Unknown";
                        string dataType = dataTypeProperty?.GetValue(value)?.ToString() ?? "String";
                        bool isMultiValued = isMultiValuedProperty?.GetValue(value) as bool? ?? false;
                        bool isAnchor = isAnchorProperty?.GetValue(value) as bool? ?? false;
                        
                        // Use proper property name escaping for the hashtable
                        string nameKey = EscapePropertyName("Name");
                        string dataTypeKey = EscapePropertyName("DataType");
                        string multiValuedKey = EscapePropertyName("IsMultiValued");
                        string anchorKey = EscapePropertyName("IsAnchor");
                        
                        return "@{" + nameKey + "='" + name + "'; " + dataTypeKey + "='" + dataType + "'; " + multiValuedKey + "=$" + (isMultiValued ? "true" : "false") + "; " + anchorKey + "=$" + (isAnchor ? "true" : "false") + "}";
                    }
                    catch (Exception ex)
                    {
                        Tracer.TraceWarning("failed-to-extract-schema-attribute-info: {0}", 0, ex.Message);
                        return "@{Name='Unknown'; DataType='String'; IsMultiValued=$false; IsAnchor=$false}";
                    }
                }
                
                // For other MetadirectoryServices objects, return a simple placeholder
                return "@{Type='" + value.GetType().Name + "'}";
            }
            
            // If it looks like a type name, treat it as an empty string to avoid command line issues
            if (stringValue.StartsWith("System.") || stringValue.Contains("Version=") || stringValue.Contains("Culture="))
            {
                Tracer.TraceWarning("converting-complex-object-to-empty-string: {0}", 0, stringValue);
                return "\"\"";
            }
            
            // Escape and quote the string representation
            if (stringValue.Contains(" ") || stringValue.Contains("\"") || stringValue.Contains("'"))
            {
                return $"\"{stringValue.Replace("\"", "`\"")}\"";
            }
            
            return stringValue;
        }

        private Collection<PSObject> ExecutePowerShellScript(string script, PSDataCollection<PSObject> pipelineInput)
        {
            Collection<PSObject> results = new Collection<PSObject>();
            
            try
            {
                // Create a temporary script file to handle complex scenarios and pipeline input
                // Use C:\Windows\Temp instead of user-specific temp to ensure impersonated user can access it
                string tempDir = @"C:\Windows\Temp";
                if (!Directory.Exists(tempDir))
                {
                    tempDir = Path.GetTempPath(); // Fallback to default if C:\Windows\Temp doesn't exist
                }
                string tempScriptPath = Path.Combine(tempDir, $"PSMA_PS7_TempScript_{Guid.NewGuid()}.ps1");
                Tracer.TraceInformation("powershell7-creating-temp-script: {0}", tempScriptPath);
                
                try
                {
                    // Build the complete script with variable injection and pipeline handling
                    StringBuilder scriptBuilder = new StringBuilder();
                    
                    // Set PSMA engine identification variables (non-intrusive)
                    scriptBuilder.AppendLine("# PowerShell 7+ Out-of-Process PSMA Engine");
                    scriptBuilder.AppendLine("$global:PSMA_ENGINE = 'PowerShell7-OutOfProcess'");
                    scriptBuilder.AppendLine("$global:PS7ENGINE = $true");
                    
                    // Set additional engine identification variables for compatibility with Windows PowerShell 5.1
                    scriptBuilder.AppendLine("# Engine compatibility variables");
                    scriptBuilder.AppendLine("$global:PSMAEngineType = 'PowerShell 7+ (Out-of-Process)'");
                    scriptBuilder.AppendLine("$global:PSMAEngineVersion = '7.0'");
                    scriptBuilder.AppendLine("$global:PSMAEngineSelected = 'PowerShell 7+ (Out-of-Process)'");
                    scriptBuilder.AppendLine("");
                    
                    // Inject session variables (if any were set)
                    if (sessionVariables != null && sessionVariables.Count > 0)
                    {
                        scriptBuilder.AppendLine("# Session variables");
                        foreach (var variable in sessionVariables)
                        {
                            scriptBuilder.AppendLine($"$global:{variable.Key} = {ConvertToLiteral(variable.Value)}");
                        }
                    }
                    
                    // Execute the original script without modification
                    scriptBuilder.AppendLine("# Execute main script");
                    scriptBuilder.AppendLine(script);
                    
                    // Add output serialization to capture PowerShell objects properly
                    scriptBuilder.AppendLine("");
                    scriptBuilder.AppendLine("# Serialize any pipeline output to capture PSObjects");
                    scriptBuilder.AppendLine("# This ensures PSMA can receive the objects properly");
                    
                    // Write script to temporary file
                    string fullScript = scriptBuilder.ToString();
                    Tracer.TraceInformation("powershell7-script-length: {0} chars", fullScript.Length);
                    Tracer.TraceInformation("powershell7-writing-script-to: {0}", tempScriptPath);
                    
                    // Log first few lines of the script for debugging
                    string[] scriptLines = fullScript.Split(new[] { Environment.NewLine }, StringSplitOptions.None);
                    Tracer.TraceInformation("powershell7-script-preview-first-10-lines:");
                    for (int i = 0; i < Math.Min(10, scriptLines.Length); i++)
                    {
                        Tracer.TraceInformation("  Line {0}: {1}", i + 1, scriptLines[i]);
                    }
                    
                    File.WriteAllText(tempScriptPath, fullScript, Encoding.UTF8);
                    Tracer.TraceInformation("powershell7-script-written-successfully-file-size: {0} bytes", new FileInfo(tempScriptPath).Length);
                    
                    // Execute PowerShell 7+ process  
                    using (var process = new Process())
                    {
                        process.StartInfo.FileName = powerShell7ExecutablePath;
                        process.StartInfo.Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{tempScriptPath}\"";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.RedirectStandardError = true;
                        process.StartInfo.CreateNoWindow = true;
                        
                        // Set working directory to a location accessible by the impersonated user
                        // Avoid using the service user's temp directory when impersonating
                        process.StartInfo.WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
                        
                        // Configure impersonation if credentials are provided
                        var impersonationUsername = GetVariable("_ImpersonationUsername") as string;
                        var impersonationDomain = GetVariable("_ImpersonationDomain") as string;
                        var impersonationPassword = GetVariable("_ImpersonationPassword") as string;
                        
                        bool impersonationConfigured = false;
                        if (!string.IsNullOrEmpty(impersonationUsername) && !string.IsNullOrEmpty(impersonationPassword))
                        {
                            try
                            {
                                Tracer.TraceInformation("configuring-powershell7-process-with-impersonation domain: '{0}', username: '{1}'", impersonationDomain ?? "", impersonationUsername);
                                
                                // Configure process to run under specified credentials
                                process.StartInfo.UserName = impersonationUsername;
                                process.StartInfo.Domain = impersonationDomain ?? "";
                                
                                // Convert password to SecureString
                                var securePassword = new System.Security.SecureString();
                                foreach (char c in impersonationPassword)
                                {
                                    securePassword.AppendChar(c);
                                }
                                securePassword.MakeReadOnly();
                                process.StartInfo.Password = securePassword;
                                
                                // Required for impersonation
                                process.StartInfo.LoadUserProfile = true;
                                impersonationConfigured = true;
                                
                                Tracer.TraceInformation("powershell7-process-configured-for-impersonation");
                            }
                            catch (Exception ex)
                            {
                                Tracer.TraceError($"failed-to-configure-powershell7-impersonation: {ex.Message}");
                                throw new System.Security.SecurityException($"Failed to configure PowerShell 7+ impersonation: {ex.Message}. Verify the credentials are correct and the account has the required permissions.", ex);
                            }
                        }
                        
                        if (!impersonationConfigured)
                        {
                            Tracer.TraceInformation("powershell7-will-run-as-sync-service-account");
                        }
                        
                        Tracer.TraceInformation("starting-powershell7-process: {0} {1}", process.StartInfo.FileName, process.StartInfo.Arguments?.Replace("{", "{{").Replace("}", "}}"));
                        Tracer.TraceInformation("working-directory: {0}", process.StartInfo.WorkingDirectory);
                        Tracer.TraceInformation("impersonation-configured: {0}", impersonationConfigured);
                        
                        try
                        {
                            Tracer.TraceInformation("starting-powershell7-process-with-enhanced-error-handling");
                            process.Start();
                            
                            // Monitor process to detect early crashes
                            System.Threading.Thread.Sleep(500); // Give process time to initialize
                            
                            if (process.HasExited)
                            {
                                Tracer.TraceError($"powershell7-process-exited-immediately exit-code: {process.ExitCode}");
                                
                                if (impersonationConfigured)
                                {
                                    string troubleshootingMessage;
                                    switch (process.ExitCode)
                                    {
                                        case -1073741502: // STATUS_DLL_INIT_FAILED (0xC0000142)
                                            troubleshootingMessage = $"PowerShell 7 with impersonation failed with DLL initialization error (exit code {process.ExitCode}). " +
                                                "Common causes: 1) Missing Visual C++ Redistributables for VS 2019 x64, " +
                                                "2) Corrupted PowerShell 7 installation, " +
                                                "3) Antivirus blocking CreateProcessWithTokenW, " +
                                                "4) User profile corruption for the impersonated account. " +
                                                "Falling back to Windows PowerShell 5.1.";
                                            break;
                                        default:
                                            troubleshootingMessage = $"PowerShell 7 with impersonation crashed immediately (exit code {process.ExitCode}). " +
                                                "Verify: 1) PowerShell 7 installation integrity, " +
                                                "2) Required privileges are granted, " +
                                                "3) No antivirus interference, " +
                                                "4) User profile accessibility. " +
                                                "Falling back to Windows PowerShell 5.1.";
                                            break;
                                    }
                                    
                                    throw new PowerShell7ImpersonationException(
                                        troubleshootingMessage,
                                        shouldFallback: true);
                                }
                                else
                                {
                                    string errorMessage = process.ExitCode == -1073741502 
                                        ? $"PowerShell 7 process crashed with DLL initialization error (exit code {process.ExitCode}). Check Visual C++ Redistributables and PowerShell 7 installation."
                                        : $"PowerShell 7 process crashed immediately with exit code {process.ExitCode}. This is often due to impersonation issues.";
                                    throw new InvalidOperationException(errorMessage);
                                }
                            }
                            
                            string output = process.StandardOutput.ReadToEnd();
                            string error = process.StandardError.ReadToEnd();
                            
                            process.WaitForExit();
                            
                            Tracer.TraceInformation("powershell7-process-exit-code: {0}", process.ExitCode);
                            Tracer.TraceInformation("powershell7-process-output-length: {0} chars", output?.Length ?? 0);
                            
                            if (!string.IsNullOrEmpty(error))
                            {
                                Tracer.TraceError($"powershell7-process-error: {error}");
                            }
                            
                            // For import scripts, the output might be objects that need to be captured
                            // We'll process any output that comes back through stdout
                            if (!string.IsNullOrEmpty(output))
                            {
                                Tracer.TraceInformation("powershell7-processing-output");
                                
                                // Try to parse output as PowerShell objects
                                // Since we're out-of-process, complex objects will be serialized as text
                                string[] outputLines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                                
                                foreach (string line in outputLines)
                                {
                                    if (!string.IsNullOrWhiteSpace(line))
                                    {
                                        // Create PSObject from output line
                                        // This preserves the text format for PSMA processing
                                        PSObject psObject = new PSObject(line.Trim());
                                        results.Add(psObject);
                                        Tracer.TraceInformation("added-output-object: {0}", line.Trim());
                                    }
                                }
                            }
                            
                            // Check for specific error conditions
                            if (process.ExitCode == -1073741502) // 0xc0000142 as signed int
                            {
                                // Detect OS version to provide appropriate error handling
                                Version osVersion = System.Environment.OSVersion.Version;
                                bool isServer2012R2 = osVersion.Major == 6 && osVersion.Minor == 3;
                                
                                Tracer.TraceError($"powershell7-process-failed-0xc0000142 os-version: {osVersion.Major}.{osVersion.Minor}.{osVersion.Build}, is-server2012r2: {isServer2012R2}, impersonation-configured: {impersonationConfigured}");
                                
                                if (impersonationConfigured)
                                {
                                    if (isServer2012R2)
                                    {
                                        // Known Server 2012 R2 compatibility issue
                                        throw new PowerShell7ImpersonationException(
                                            "PowerShell 7 with impersonation is not compatible on Windows Server 2012 R2 (process crash 0xc0000142). " +
                                            "To resolve this issue: " +
                                            "1) Use PowerShell 7 without impersonation (run as service account), or " +
                                            "2) Use Windows PowerShell 5.1 with impersonation, or " +
                                            "3) Upgrade to Windows Server 2016 or later for full PowerShell 7 + impersonation support.",
                                            shouldFallback: true);
                                    }
                                    else
                                    {
                                        // Different issue on newer OS - don't fallback automatically
                                        throw new InvalidOperationException(
                                            $"PowerShell 7+ process failed to start with impersonation (0xc0000142) on Windows {osVersion.Major}.{osVersion.Minor}. " +
                                            "This may be caused by: " +
                                            "1) Missing Visual C++ Redistributables for PowerShell 7, " +
                                            "2) PowerShell 7 executable path issues, " +
                                            "3) Security policy restrictions, or " +
                                            "4) Environment configuration problems. " +
                                            "Please verify PowerShell 7 installation and try running without impersonation first.");
                                    }
                                }
                                else
                                {
                                    throw new InvalidOperationException("PowerShell 7+ process failed to initialize (0xc0000142). This is typically caused by installation or dependency issues.");
                                }
                            }
                            
                            // Don't throw error for successful execution
                            if (process.ExitCode != 0)
                            {
                                string errorMessage = $"PowerShell 7+ script execution failed with exit code {process.ExitCode}";
                                if (!string.IsNullOrEmpty(error))
                                    errorMessage += $": {error}";
                                throw new InvalidOperationException(errorMessage);
                            }
                            
                            Tracer.TraceInformation("powershell7-script-completed-successfully-objects-returned: {0}", results.Count);
                        }
                        catch (System.ComponentModel.Win32Exception win32Ex)
                        {
                            Tracer.TraceError($"powershell7-process-start-win32-error: {win32Ex.Message} (Code: {win32Ex.NativeErrorCode})");
                            
                            // Check for impersonation-related errors and recommend fallback
                            bool isImpersonationError = impersonationConfigured && (
                                win32Ex.NativeErrorCode == 1326 ||  // Invalid credentials
                                win32Ex.NativeErrorCode == 1331 ||  // Account restrictions
                                win32Ex.NativeErrorCode == 1332 ||  // Account locked
                                win32Ex.NativeErrorCode == 1355 ||  // Domain issues
                                win32Ex.NativeErrorCode == 5        // Access denied
                            );
                            
                            // Provide specific error messages for common impersonation issues
                            string errorMessage;
                            switch (win32Ex.NativeErrorCode)
                            {
                                case 1326:
                                    errorMessage = "Failed to start PowerShell 7+ process: Invalid username or password for impersonation.";
                                    break;
                                case 1331:
                                    errorMessage = "Failed to start PowerShell 7+ process: Account restrictions prevent impersonation (account may be disabled or locked).";
                                    break;
                                case 1332:
                                    errorMessage = "Failed to start PowerShell 7+ process: Account is locked out.";
                                    break;
                                case 1355:
                                    errorMessage = "Failed to start PowerShell 7+ process: Domain does not exist or cannot be contacted.";
                                    break;
                                case 5:
                                    errorMessage = "Failed to start PowerShell 7+ process: Access denied. The impersonation account may not have the required 'Log on as a service' right.";
                                    break;
                                default:
                                    errorMessage = $"Failed to start PowerShell 7+ process: {win32Ex.Message} (Code: {win32Ex.NativeErrorCode})";
                                    break;
                            }
                            
                            if (impersonationConfigured)
                            {
                                errorMessage += " Please verify the impersonation credentials and account permissions.";
                            }
                            
                            // For impersonation errors, throw our custom exception with clear guidance
                            if (isImpersonationError)
                            {
                                throw new PowerShell7ImpersonationException(
                                    $"PowerShell 7 with impersonation is not compatible on Windows Server 2012 R2. " +
                                    $"Error: {errorMessage} " +
                                    $"To resolve this issue: " +
                                    $"1) Use PowerShell 7 without impersonation (run as service account), or " +
                                    $"2) Use Windows PowerShell 5.1 with impersonation, or " +
                                    $"3) Upgrade to Windows Server 2016 or later for full PowerShell 7 + impersonation support.", 
                                    win32Ex, 
                                    shouldFallback: true);
                            }
                            else
                            {
                                throw new System.Security.SecurityException(errorMessage, win32Ex);
                            }
                        }
                        catch (InvalidOperationException ex) when (ex.Message.Contains("exit code"))
                        {
                            // Re-throw script execution errors as-is
                            throw;
                        }
                        catch (Exception ex)
                        {
                            Tracer.TraceError("powershell7-process-unexpected-error", ex);
                            throw new InvalidOperationException($"Unexpected error during PowerShell 7+ execution: {ex.Message}", ex);
                        }
                    }
                }
                finally
                {
                    // Clean up temporary script file
                    try
                    {
                        if (File.Exists(tempScriptPath))
                        {
                            File.Delete(tempScriptPath);
                        }
                    }
                    catch (Exception ex)
                    {
                        Tracer.TraceWarning($"failed-to-delete-temp-script-file: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Tracer.TraceError("execute-powershell7-script-error", ex);
                throw;
            }
            
            return results;
        }

        private object ConvertFromJSONString(string jsonString, string typeName)
        {
            if (jsonString == null)
                return null;

            // Handle simple types directly without JSON serialization
            switch (typeName)
            {
                case "System.Boolean":
                    if (bool.TryParse(jsonString, out bool boolResult))
                        return boolResult;
                    break;
                case "System.Int32":
                    if (int.TryParse(jsonString, out int intResult))
                        return intResult;
                    break;
                case "System.Double":
                    if (double.TryParse(jsonString, out double doubleResult))
                        return doubleResult;
                    break;
                case "System.Decimal":
                    if (decimal.TryParse(jsonString, out decimal decimalResult))
                        return decimalResult;
                    break;
                case "System.String":
                    return jsonString;
                case "System.Object":
                    return jsonString; // Handle null case
            }

            // For complex types, try JSON deserialization
            try
            {
                Type targetType = Type.GetType(typeName);
                if (targetType != null)
                {
                    var serializer = new DataContractJsonSerializer(targetType);
                    using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(jsonString)))
                    {
                        return serializer.ReadObject(stream);
                    }
                }
            }
            catch
            {
                // If JSON deserialization fails, return as string
                return jsonString;
            }

            // Fallback to string
            return jsonString;
        }

        /// <summary>
        /// Serializes a pipeline PSObject for recreation in the PowerShell 7 child process
        /// </summary>
        private string SerializePipelineObject(PSObject psobject)
        {
            if (psobject == null)
                return "$null";

            try
            {
                // Handle different types of objects
                var baseObject = psobject.BaseObject;
                
                if (baseObject == null)
                {
                    return "$null";
                }
                
                // For hashtables, serialize as hashtable literal
                if (baseObject is System.Collections.Hashtable hashtable)
                {
                    var items = new List<string>();
                    foreach (System.Collections.DictionaryEntry entry in hashtable)
                    {
                        string key = EscapePropertyName(entry.Key?.ToString() ?? "null");
                        string value = ConvertToLiteral(entry.Value);
                        items.Add(key + " = " + value);
                    }
                    return "@{ " + string.Join("; ", items) + " }";
                }
                
                // For PSCustomObject or objects with properties, create a hashtable representation
                // Use Members collection to capture ALL properties including control properties like [ObjectModificationType]
                var propItems = new List<string>();
                
                // First, try to get all members (this includes NoteProperties added by PSMA)
                foreach (var member in psobject.Members)
                {
                    try
                    {
                        // Only process properties and note properties (not methods, scripts, etc.)
                        if (member.MemberType == PSMemberTypes.Property || 
                            member.MemberType == PSMemberTypes.NoteProperty ||
                            member.MemberType == PSMemberTypes.ScriptProperty)
                        {
                            string propName = EscapePropertyName(member.Name);
                            object propValue = member.Value;
                            string serializedValue = ConvertToLiteral(propValue);
                            propItems.Add(propName + " = " + serializedValue);
                            
                            // Add debug tracing for control properties
                            if (member.Name.StartsWith("[") && member.Name.EndsWith("]"))
                            {
                                Tracer.TraceInformation("pipeline-object-control-property: {0} = {1}", member.Name, member.Value);
                            }
                        }
                    }
                    catch (Exception memberEx)
                    {
                        Tracer.TraceWarning("pipeline-object-member-serialization-failed: {0}, error: {1}", 0, member.Name, memberEx.Message);
                        // Skip problematic properties
                    }
                }
                
                // Fallback: if Members didn't give us properties, try Properties collection
                if (propItems.Count == 0)
                {
                    var properties = psobject.Properties;
                    if (properties != null && properties.Any())
                    {
                        foreach (var prop in properties)
                        {
                            try
                            {
                                string propName = EscapePropertyName(prop.Name);
                                object propValue = prop.Value;
                                string serializedValue = ConvertToLiteral(propValue);
                                propItems.Add(propName + " = " + serializedValue);
                            }
                            catch (Exception propEx)
                            {
                                Tracer.TraceWarning("pipeline-object-property-serialization-failed: {0}, error: {1}", 0, prop.Name, propEx.Message);
                                // Skip problematic properties
                            }
                        }
                    }
                }
                
                if (propItems.Count > 0)
                {
                    // Create a PSCustomObject from hashtable
                    var result = "[PSCustomObject]@{ " + string.Join("; ", propItems) + " }";
                    Tracer.TraceInformation("pipeline-object-serialized-with-properties: count={0}, length={1}", propItems.Count, result.Length);
                    return result;
                }
                
                // Handle arrays and collections (multivalues)
                if (baseObject is System.Collections.IEnumerable enumerable && !(baseObject is string))
                {
                    var items = new List<string>();
                    foreach (var item in enumerable)
                    {
                        items.Add(ConvertToLiteral(item));
                    }
                    return $"@({string.Join(", ", items)})";
                }
                
                // Handle DateTime objects specifically
                if (baseObject is DateTime dateTime)
                {
                    return $"[DateTime]'{dateTime:yyyy-MM-ddTHH:mm:ss.fffffffK}'";
                }
                
                // Handle Guid objects specifically
                if (baseObject is Guid guid)
                {
                    return $"[Guid]'{guid}'";
                }
                
                // For primitive types, use direct conversion
                if (baseObject is string || baseObject is int || baseObject is long || 
                    baseObject is double || baseObject is decimal || baseObject is bool)
                {
                    return ConvertToLiteral(baseObject);
                }
                
                // Fallback: try to serialize as string
                return ConvertToLiteral(baseObject.ToString());
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning("pipeline-object-serialization-failed: {0}", 0, ex.Message);
                // Return a string representation as fallback
                return ConvertToLiteral(psobject.ToString());
            }
        }

        private string ConvertToLiteral(object value)
        {
            if (value == null)
                return "$null";
                
            if (value is string str)
                return $"'{str.Replace("'", "''")}'";
                
            if (value is bool boolean)
                return boolean ? "$true" : "$false";
                
            if (value is int || value is long || value is double || value is decimal || value is float)
                return value.ToString();
                
            if (value is DateTime dateTime)
                return $"[DateTime]'{dateTime:yyyy-MM-ddTHH:mm:ss.fffffffK}'";
                
            if (value is Guid guid)
                return $"[Guid]'{guid}'";
                
            if (value is byte[] byteArray)
                return $"[byte[]]@({string.Join(", ", byteArray.Select(b => b.ToString()))})";
                
            // Handle arrays and collections
            if (value is System.Collections.IEnumerable enumerable && !(value is string))
            {
                var items = new List<string>();
                foreach (var item in enumerable)
                {
                    items.Add(ConvertToLiteral(item));
                }
                return $"@({string.Join(", ", items)})";
            }
                
            // Handle enums
            if (value is Enum enumValue)
                return $"[{value.GetType().FullName}]::{enumValue}";
                
            // For complex objects, convert to string representation
            return $"'{value.ToString().Replace("'", "''")}'";
        }

        /// <summary>
        /// Escapes property names that contain special PowerShell characters that would break hashtable syntax
        /// This fixes the serialization issue with attribute names like "-dn-" in Schema objects
        /// </summary>
        private string EscapePropertyName(string propertyName)
        {
            if (string.IsNullOrEmpty(propertyName))
                return "''";
            
            // PowerShell hashtable keys with special characters must be quoted
            // Check for characters that require quoting in hashtable key names
            if (propertyName.Contains("-") || 
                propertyName.Contains(" ") || 
                propertyName.Contains(".") ||
                propertyName.Contains("@") ||
                propertyName.Contains("#") ||
                propertyName.Contains("$") ||
                propertyName.Contains("%") ||
                propertyName.Contains("^") ||
                propertyName.Contains("&") ||
                propertyName.Contains("*") ||
                propertyName.Contains("(") ||
                propertyName.Contains(")") ||
                propertyName.Contains("+") ||
                propertyName.Contains("=") ||
                propertyName.Contains("{") ||
                propertyName.Contains("}") ||
                propertyName.Contains("[") ||
                propertyName.Contains("]") ||
                propertyName.Contains("\\") ||
                propertyName.Contains("|") ||
                propertyName.Contains(";") ||
                propertyName.Contains(":") ||
                propertyName.Contains("\"") ||
                propertyName.Contains("'") ||
                propertyName.Contains("<") ||
                propertyName.Contains(">") ||
                propertyName.Contains(",") ||
                propertyName.Contains("?") ||
                propertyName.Contains("/") ||
                propertyName.StartsWith("_") ||
                char.IsDigit(propertyName[0]))  // Property names starting with digits need quoting
            {
                // Quote the property name and escape internal single quotes
                return $"'{propertyName.Replace("'", "''")}'";
            }
            
            // Property name is safe to use unquoted
            return propertyName;
        }

        public void SetVariable(string name, object value)
        {
            try
            {
                Tracer.TraceInformation("setting-variable-powershell7-outofprocess '{0}' = '{1}'", name, value);
                sessionVariables[name] = value;
            }
            catch (Exception ex)
            {
                Tracer.TraceError("set-powershell7-variable-error", ex);
                throw;
            }
        }

        public object GetVariable(string name)
        {
            try
            {
                Tracer.TraceInformation("getting-variable-powershell7-outofprocess '{0}'", name);
                return sessionVariables.ContainsKey(name) ? sessionVariables[name] : null;
            }
            catch (Exception ex)
            {
                Tracer.TraceError("get-powershell7-variable-error", ex);
                return null;
            }
        }

        // Method to check if impersonation is requested - used by MA to decide on fallback
        public bool IsImpersonationRequested()
        {
            var impersonationRequested = GetVariable("_ImpersonationRequested");
            var hasCredentials = impersonationRequested != null && (bool)impersonationRequested;
            
            // For PowerShell 7, we now support impersonation, so return the actual status
            return hasCredentials;
        }

        private void Error_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<ErrorRecord> err = (PSDataCollection<ErrorRecord>)sender;
                if (err != null && e.Index < err.Count)
                {
                    var errorId = err[e.Index].Exception?.HResult ?? -1;
                    var errorMessage = err[e.Index].FullyQualifiedErrorId ?? "unknown";
                    var errorDetails = err[e.Index].ToString() ?? "no details";
                    Tracer.TraceError($"powershell7-error id: {errorId}, message: {errorMessage}, details: {errorDetails}");
                    PowerShellError?.Invoke(sender, e);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning($"powershell7-error-handler-exception: {ex.Message}");
            }
        }

        private void Verbose_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<VerboseRecord> verbose = (PSDataCollection<VerboseRecord>)sender;
                if (verbose != null && e.Index < verbose.Count)
                {
                    Tracer.TraceInformation("powershell7-verbose {0}", verbose[e.Index].ToString());
                    PowerShellVerbose?.Invoke(sender, e);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning($"powershell7-verbose-handler-exception: {ex.Message}");
            }
        }

        private void Warning_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<WarningRecord> warnings = (PSDataCollection<WarningRecord>)sender;
                if (warnings != null && e.Index < warnings.Count)
                {
                    Tracer.TraceWarning($"powershell7-warning: {warnings[e.Index]}");
                    PowerShellWarning?.Invoke(sender, e);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning($"powershell7-warning-handler-exception: {ex.Message}");
            }
        }

        private void Debug_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<DebugRecord> debug = (PSDataCollection<DebugRecord>)sender;
                if (debug != null && e.Index < debug.Count)
                {
                    Tracer.TraceInformation("powershell7-debug {0}", debug[e.Index].ToString());
                    PowerShellDebug?.Invoke(sender, e);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning($"powershell7-debug-handler-exception: {ex.Message}");
            }
        }

        private void Progress_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<ProgressRecord> progress = (PSDataCollection<ProgressRecord>)sender;
                if (progress != null && e.Index < progress.Count)
                {
                    Tracer.TraceInformation("powershell7-progress {0}", progress[e.Index].ToString());
                    PowerShellProgress?.Invoke(sender, e);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning($"powershell7-progress-handler-exception: {ex.Message}");
            }
        }

        private void Runspace_AvailabilityChanged(object sender, RunspaceAvailabilityEventArgs e)
        {
            try
            {
                if (e != null)
                {
                    Tracer.TraceInformation("powershell7-runspace-availability {0}", e.RunspaceAvailability);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning($"powershell7-availability-handler-exception: {ex.Message}");
            }
        }

        private void Runspace_StateChanged(object sender, RunspaceStateEventArgs e)
        {
            try
            {
                if (e?.RunspaceStateInfo != null)
                {
                    Tracer.TraceInformation("powershell7-runspace-state-changed-to {0}", e.RunspaceStateInfo.State);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning($"powershell7-state-handler-exception: {ex.Message}");
            }
        }

        public void Dispose()
        {
            if (!disposed)
            {
                try
                {
                    CloseRunspace();
                }
                catch (Exception ex)
                {
                    Tracer.TraceWarning($"dispose-powershell7-error: {ex.Message}");
                }
                disposed = true;
            }
        }
    }
}
