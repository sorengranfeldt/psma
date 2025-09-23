using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Collections.Generic;
using System.Linq;

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
                    Tracer.TraceError("impersonation-credential-validation-failed-for-powershell7: {0}", ex.Message);
                    
                    // Determine if this is a credential issue or a platform limitation
                    string platformInfo = System.Environment.OSVersion.VersionString;
                    bool isServer2012R2 = platformInfo.Contains("6.3") || platformInfo.Contains("2012");
                    
                    string errorMessage = isServer2012R2 
                        ? $"PowerShell 7+ impersonation is not supported on Windows Server 2012 R2 due to platform limitations. Credential validation failed: {ex.Message}. Please use Windows PowerShell 5.1 for operations requiring impersonation, or configure PowerShell 7+ to run without impersonation (as the synchronization service account)."
                        : $"PowerShell 7+ impersonation credential validation failed: {ex.Message}. Please verify the domain, username, and password are correct.";
                        
                    throw new System.Security.SecurityException(errorMessage, ex);
                }
            }
            else if (hasUsername || hasPassword)
            {
                // Partial credentials provided - likely UI persistence bug
                Tracer.TraceWarning("powershell7-partial-impersonation-credentials-detected username-provided: '{0}', password-provided: '{1}'", 1, hasUsername ? "true" : "false");
                Tracer.TraceWarning("powershell7-ignoring-partial-credentials-running-without-impersonation", 1);
                
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

        public void Initialize()
        {
            Tracer.TraceInformation("*** INITIALIZING OUT-OF-PROCESS POWERSHELL 7+ ENGINE ***");
            Tracer.TraceInformation("powershell7-executable-path: {0}", powerShell7ExecutablePath);
            
            // Verify PowerShell 7 is available
            if (!File.Exists(powerShell7ExecutablePath))
            {
                string errorMessage = $"PowerShell 7+ executable not found at: {powerShell7ExecutablePath}";
                Tracer.TraceError("powershell7-not-found: {0}", errorMessage);
                throw new FileNotFoundException(errorMessage);
            }

            // Verify PowerShell 7 version
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = powerShell7ExecutablePath;
                    process.StartInfo.Arguments = "-NoProfile -NonInteractive -Command \"$PSVersionTable.PSVersion.ToString(); $PSVersionTable.PSEdition\"";
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
                        Tracer.TraceError("powershell7-version-check-failed exit-code: {0}, error: {1}", process.ExitCode, error);
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
                    Tracer.TraceError("powershell7-error-extracting-script-path: {0}", ex.Message);
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
                Tracer.TraceError("invokepowershellscript-powershell7-outofprocess", ex);
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
                
                // Execute PowerShell 7+ process with the script file
                using (var process = new Process())
                {
                    process.StartInfo.FileName = powerShell7ExecutablePath;
                    
                    // Build arguments: script path + parameters
                    var argumentsBuilder = new StringBuilder();
                    argumentsBuilder.Append($"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{scriptPath}\"");
                    
                    // Add parameters if any
                    if (parameters != null && parameters.Count > 0)
                    {
                        foreach (CommandParameter param in parameters)
                        {
                            if (param.Value != null)
                            {
                                argumentsBuilder.Append($" -{param.Name} {EscapeParameterValue(param.Value)}");
                            }
                            else
                            {
                                // Switch parameter (no value)
                                argumentsBuilder.Append($" -{param.Name}");
                            }
                        }
                    }
                    
                    process.StartInfo.Arguments = argumentsBuilder.ToString();
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.WorkingDirectory = Path.GetDirectoryName(scriptPath);
                    
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
                            Tracer.TraceError("failed-to-configure-powershell7-impersonation: {0}", ex.Message);
                            throw new System.Security.SecurityException($"Failed to configure PowerShell 7+ impersonation: {ex.Message}. Verify the credentials are correct and the account has the required permissions.", ex);
                        }
                    }
                    
                    if (!impersonationConfigured)
                    {
                        Tracer.TraceInformation("powershell7-will-run-as-sync-service-account");
                    }
                    
                    // Set session variables as environment variables for the process
                    if (sessionVariables != null && sessionVariables.Count > 0)
                    {
                        foreach (var variable in sessionVariables)
                        {
                            // Skip impersonation variables (they're handled separately)
                            if (!variable.Key.StartsWith("_Impersonation"))
                            {
                                string envValue = variable.Value?.ToString() ?? "";
                                process.StartInfo.EnvironmentVariables[$"PSMA_{variable.Key}"] = envValue;
                                Tracer.TraceInformation("powershell7-set-environment-variable: PSMA_{0} = {1}", variable.Key, envValue);
                            }
                        }
                    }
                    
                    Tracer.TraceInformation("starting-powershell7-process: {0} {1}", process.StartInfo.FileName, process.StartInfo.Arguments);
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
                            Tracer.TraceError("powershell7-process-exited-immediately exit-code: {0}", process.ExitCode);
                            throw new InvalidOperationException($"PowerShell 7+ process crashed immediately with exit code {process.ExitCode}. This is often due to impersonation issues.");
                        }
                        
                        string output = process.StandardOutput.ReadToEnd();
                        string error = process.StandardError.ReadToEnd();
                        
                        process.WaitForExit();
                        
                        Tracer.TraceInformation("powershell7-process-exit-code: {0}", process.ExitCode);
                        Tracer.TraceInformation("powershell7-process-output-length: {0} chars", output?.Length ?? 0);
                        
                        if (!string.IsNullOrEmpty(error))
                        {
                            Tracer.TraceError("powershell7-process-error: {0}", error);
                        }
                        
                        // Process output as PowerShell objects
                        if (!string.IsNullOrEmpty(output))
                        {
                            Tracer.TraceInformation("powershell7-processing-output");
                            
                            string[] outputLines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                            
                            foreach (string line in outputLines)
                            {
                                if (!string.IsNullOrWhiteSpace(line))
                                {
                                    PSObject psObject = new PSObject(line.Trim());
                                    results.Add(psObject);
                                    Tracer.TraceInformation("added-output-object: {0}", line.Trim());
                                }
                            }
                        }
                        
                        // Check for specific error conditions
                        if (process.ExitCode == -1073741502) // 0xc0000142 as signed int
                        {
                            throw new InvalidOperationException("PowerShell 7+ process failed to initialize (0xc0000142). This is typically caused by impersonation or security policy issues.");
                        }
                        
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
                        Tracer.TraceError("powershell7-process-start-win32-error: {0} (Code: {1})", win32Ex.Message, win32Ex.NativeErrorCode);
                        
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
                Tracer.TraceError("ExecutePowerShellFile-error: {0}", ex.Message);
                throw new InvalidOperationException($"Unexpected error during PowerShell 7+ execution: {ex.Message}", ex);
            }
            
            return results;
        }

        private string EscapeParameterValue(object value)
        {
            if (value == null)
                return "$null";
                
            string stringValue = value.ToString();
            
            // If the value contains spaces or special characters, wrap in quotes and escape quotes
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
                string tempScriptPath = Path.GetTempFileName() + ".ps1";
                Tracer.TraceInformation("powershell7-creating-temp-script: {0}", tempScriptPath);
                
                try
                {
                    // Build the complete script with variable injection and pipeline handling
                    StringBuilder scriptBuilder = new StringBuilder();
                    
                    // Set PSMA engine identification variables (non-intrusive)
                    scriptBuilder.AppendLine("# PowerShell 7+ Out-of-Process PSMA Engine");
                    scriptBuilder.AppendLine("$global:PSMA_ENGINE = 'PowerShell7-OutOfProcess'");
                    scriptBuilder.AppendLine("$global:PS7ENGINE = $true");
                    
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
                        process.StartInfo.WorkingDirectory = Path.GetDirectoryName(tempScriptPath);
                        
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
                                Tracer.TraceError("failed-to-configure-powershell7-impersonation: {0}", ex.Message);
                                throw new System.Security.SecurityException($"Failed to configure PowerShell 7+ impersonation: {ex.Message}. Verify the credentials are correct and the account has the required permissions.", ex);
                            }
                        }
                        
                        if (!impersonationConfigured)
                        {
                            Tracer.TraceInformation("powershell7-will-run-as-sync-service-account");
                        }
                        
                        Tracer.TraceInformation("starting-powershell7-process: {0} {1}", process.StartInfo.FileName, process.StartInfo.Arguments);
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
                                Tracer.TraceError("powershell7-process-exited-immediately exit-code: {0}", process.ExitCode);
                                
                                if (impersonationConfigured)
                                {
                                    throw new PowerShell7ImpersonationException(
                                        $"PowerShell 7 with impersonation crashed immediately (exit code {process.ExitCode}) - not compatible on Windows Server 2012 R2. " +
                                        "To resolve this issue: " +
                                        "1) Use PowerShell 7 without impersonation (run as service account), or " +
                                        "2) Use Windows PowerShell 5.1 with impersonation, or " +
                                        "3) Upgrade to Windows Server 2016 or later for full PowerShell 7 + impersonation support.",
                                        shouldFallback: true);
                                }
                                else
                                {
                                    throw new InvalidOperationException($"PowerShell 7+ process crashed immediately with exit code {process.ExitCode}. This is often due to impersonation issues.");
                                }
                            }
                            
                            string output = process.StandardOutput.ReadToEnd();
                            string error = process.StandardError.ReadToEnd();
                            
                            process.WaitForExit();
                            
                            Tracer.TraceInformation("powershell7-process-exit-code: {0}", process.ExitCode);
                            Tracer.TraceInformation("powershell7-process-output-length: {0} chars", output?.Length ?? 0);
                            
                            if (!string.IsNullOrEmpty(error))
                            {
                                Tracer.TraceError("powershell7-process-error: {0}", error);
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
                                if (impersonationConfigured)
                                {
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
                                    throw new InvalidOperationException("PowerShell 7+ process failed to initialize (0xc0000142). This is typically caused by impersonation or security policy issues.");
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
                            Tracer.TraceError("powershell7-process-start-win32-error: {0} (Code: {1})", win32Ex.Message, win32Ex.NativeErrorCode);
                            
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
                        Tracer.TraceWarning("failed-to-delete-temp-script-file", 1, ex.Message);
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

        private string ConvertToLiteral(object value)
        {
            if (value == null)
                return "$null";
                
            if (value is string str)
                return $"'{str.Replace("'", "''")}'";
                
            if (value is bool boolean)
                return boolean ? "$true" : "$false";
                
            if (value is int || value is long || value is double || value is decimal)
                return value.ToString();
                
            // For complex objects, convert to string representation
            return $"'{value.ToString().Replace("'", "''")}'";
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
                    Tracer.TraceError("powershell7-error id: {0}, message: {1}", 
                        err[e.Index].Exception?.HResult ?? -1, 
                        err[e.Index].FullyQualifiedErrorId ?? "unknown", 
                        err[e.Index].ToString() ?? "no details");
                    PowerShellError?.Invoke(sender, e);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning("powershell7-error-handler-exception", 1, ex.Message);
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
                Tracer.TraceWarning("powershell7-verbose-handler-exception", 1, ex.Message);
            }
        }

        private void Warning_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<WarningRecord> warnings = (PSDataCollection<WarningRecord>)sender;
                if (warnings != null && e.Index < warnings.Count)
                {
                    Tracer.TraceWarning("powershell7-warning", 1, warnings[e.Index]);
                    PowerShellWarning?.Invoke(sender, e);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                Tracer.TraceWarning("powershell7-warning-handler-exception", 1, ex.Message);
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
                Tracer.TraceWarning("powershell7-debug-handler-exception", 1, ex.Message);
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
                Tracer.TraceWarning("powershell7-progress-handler-exception", 1, ex.Message);
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
                Tracer.TraceWarning("powershell7-availability-handler-exception", 1, ex.Message);
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
                Tracer.TraceWarning("powershell7-state-handler-exception", 1, ex.Message);
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
                    Tracer.TraceWarning("dispose-powershell7-error", 1, ex.Message);
                }
                disposed = true;
            }
        }
    }
}
