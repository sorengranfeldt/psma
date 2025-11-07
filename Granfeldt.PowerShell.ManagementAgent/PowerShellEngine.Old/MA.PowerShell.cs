using Microsoft.MetadirectoryServices;
using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Granfeldt
{
    public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
    {
        Runspace runspace = null;
        PowerShell powershell = null;
        IPowerShellEngine powerShellEngine = null; // For PowerShell 7+ support

        void results_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<PSObject> obj = (PSDataCollection<PSObject>)sender;
                if (obj != null && e.Index < obj.Count && obj[e.Index]?.BaseObject != null)
                {
                    Tracer.TraceInformation("output-psdata-type {0}, {1}", e.Index, obj[e.Index].BaseObject.GetType());
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                try { Tracer.TraceWarning("results-handler-exception", 1, ex.Message); } catch { }
            }
        }

        void Error_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<ErrorRecord> err = (PSDataCollection<ErrorRecord>)sender;
                if (err != null && e.Index < err.Count)
                {
                    Tracer.TraceError("error id: {0}, message: {1}", 
                        err[e.Index].Exception?.HResult ?? -1, 
                        err[e.Index].FullyQualifiedErrorId ?? "unknown", 
                        err[e.Index].ToString());
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                // Log but don't throw to prevent cascading failures
                try { Tracer.TraceWarning("error-handler-exception", 1, ex.Message); } catch { }
            }
        }

        void Verbose_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<VerboseRecord> verbose = (PSDataCollection<VerboseRecord>)sender;
                if (verbose != null && e.Index < verbose.Count)
                {
                    Tracer.TraceInformation("verbose {0}", verbose[e.Index].ToString());
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                try { Tracer.TraceWarning("verbose-handler-exception", 1, ex.Message); } catch { }
            }
        }

        void Warning_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<WarningRecord> warnings = (PSDataCollection<WarningRecord>)sender;
                if (warnings != null && e.Index < warnings.Count)
                {
                    Tracer.TraceWarning("warning {0}", 1, warnings[e.Index]);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                try { Tracer.TraceWarning("warning-handler-exception", 1, ex.Message); } catch { }
            }
        }

        void Debug_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<DebugRecord> debug = (PSDataCollection<DebugRecord>)sender;
                if (debug != null && e.Index < debug.Count)
                {
                    Tracer.TraceInformation("debug {0}", debug[e.Index].ToString());
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                try { Tracer.TraceWarning("debug-handler-exception", 1, ex.Message); } catch { }
            }
        }

        void Progress_DataAdded(object sender, DataAddedEventArgs e)
        {
            try
            {
                PSDataCollection<ProgressRecord> progress = (PSDataCollection<ProgressRecord>)sender;
                if (progress != null && e.Index < progress.Count)
                {
                    Tracer.TraceInformation("progress {0}", progress[e.Index].ToString());
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                try { Tracer.TraceWarning("progress-handler-exception", 1, ex.Message); } catch { }
            }
        }

        void Runspace_AvailabilityChanged(object sender, RunspaceAvailabilityEventArgs e)
        {
            try
            {
                if (e != null)
                {
                    Tracer.TraceInformation("runspace-availability {0}", e.RunspaceAvailability);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                try { Tracer.TraceWarning("availability-handler-exception", 1, ex.Message); } catch { }
            }
        }

        void Runspace_StateChanged(object sender, RunspaceStateEventArgs e)
        {
            try
            {
                if (e?.RunspaceStateInfo != null)
                {
                    Tracer.TraceInformation("runspace-state-changed-to {0}", e.RunspaceStateInfo.State);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore
            }
            catch (Exception ex)
            {
                try { Tracer.TraceWarning("state-handler-exception", 1, ex.Message); } catch { }
            }
        }

        Collection<PSObject> InvokePowerShellScript(Command command, PSDataCollection<PSObject> pipelineInput)
        {
            return InvokePowerShellScript(command, pipelineInput, allowPowerShell7: true);
        }

        Collection<PSObject> InvokePowerShellScript(Command command, PSDataCollection<PSObject> pipelineInput, bool allowPowerShell7)
        {
            Tracer.Enter("invokepowershellscript");
            Collection<PSObject> results = new Collection<PSObject>();
            try
            {
                // Check if PowerShell 7+ is configured and available
                // Reset engine if configuration changed or if we need to switch from WinPS to PS7
                if (allowPowerShell7 && ShouldUsePowerShell7(allowForSchemaOperations: true))
                {
                    // Check if we need to create or recreate the PowerShell 7 engine
                    bool needsPowerShell7Engine = powerShellEngine == null || 
                                                  !powerShellEngine.EngineType.Contains("PowerShell 7");
                    
                    if (needsPowerShell7Engine)
                    {
                        // Dispose existing engine if it's not the right type
                        if (powerShellEngine != null && !powerShellEngine.EngineType.Contains("PowerShell 7"))
                        {
                            Tracer.TraceInformation("disposing-existing-engine-to-switch-to-powershell7 current-type: '{0}'", powerShellEngine.EngineType);
                            try
                            {
                                powerShellEngine.Dispose();
                            }
                            catch (Exception disposeEx)
                            {
                                Tracer.TraceWarning("failed-to-dispose-existing-engine", 1, disposeEx.Message);
                            }
                            powerShellEngine = null;
                        }
                        
                        if (powerShellEngine == null)
                        {
                            try
                            {
                                string ps7Path = GetPowerShell7Path();
                                Tracer.TraceInformation("*** ENHANCED POWERSHELL 7 ENGINE INITIALIZATION DEBUG ***");
                                Tracer.TraceInformation("attempting-to-use-powershell7 path: '{0}'", ps7Path);
                                Tracer.TraceInformation("powershell-version-setting: '{0}'", PowerShellVersion);
                                Tracer.TraceInformation("powershell7-path-exists: {0}", System.IO.File.Exists(ps7Path));
                                
                                Tracer.TraceInformation("creating-powershell7-engine-via-factory");
                                powerShellEngine = PowerShellEngineFactory.CreateEngine("PowerShell 7", ps7Path);
                                Tracer.TraceInformation("powershell7-engine-created-successfully type: '{0}'", powerShellEngine.GetType().Name);
                                
                                powerShellEngine.PowerShellError += PowerShellEngine_Error;
                                powerShellEngine.PowerShellVerbose += PowerShellEngine_Verbose;
                                powerShellEngine.PowerShellWarning += PowerShellEngine_Warning;
                                powerShellEngine.PowerShellDebug += PowerShellEngine_Debug;
                                powerShellEngine.PowerShellProgress += PowerShellEngine_Progress;
                                
                                Tracer.TraceInformation("initializing-powershell7-engine");
                                powerShellEngine.Initialize();
                                Tracer.TraceInformation("powershell7-engine-initialized-successfully");
                                
                                // Set impersonation credentials for PowerShell 7+ out-of-process execution
                                // Only set if we have valid credentials and we're not in configuration mode
                                if (ShouldImpersonate())
                                {
                                    try
                                    {
                                        Tracer.TraceInformation("setting-impersonation-credentials-for-powershell7-outofprocess");
                                        powerShellEngine.SetImpersonationCredentials(impersonationUsername, impersonationUserDomain, impersonationUserPassword);
                                        
                                        // PowerShell 7 now supports impersonation with credential validation
                                        // If we reach here, credentials were validated successfully
                                        Tracer.TraceInformation("powershell7-impersonation-credentials-validated-successfully");
                                    }
                                    catch (System.Security.SecurityException secEx)
                                    {
                                        Tracer.TraceError("powershell7-impersonation-credential-validation-failed: {0}", secEx.Message);
                                        
                                        // PowerShell 7+ does not support impersonation - fall back to Windows PowerShell 5.1
                                        Tracer.TraceWarning("powershell7-impersonation-not-supported-falling-back", 1, secEx.Message);
                                        throw new InvalidOperationException($"PowerShell 7+ impersonation not supported, falling back to Windows PowerShell 5.1: {secEx.Message}", secEx);
                                    }
                                    catch (Exception ex)
                                    {
                                        Tracer.TraceError("failed-to-set-impersonation-credentials-for-powershell7: {0}", ex.Message);
                                        // For other exceptions, provide clear error message
                                        throw new InvalidOperationException($"Failed to configure PowerShell 7+ impersonation: {ex.Message}", ex);
                                    }
                                }
                                
                                Tracer.TraceInformation("successfully-initialized-powershell7-engine");
                            }
                            catch (Exception ex)
                            {
                                Tracer.TraceWarning("failed-to-initialize-powershell7-fallback-to-windows-powershell", 1, ex.Message);
                                Tracer.TraceError("powershell7-initialization-error-details", ex);
                                powerShellEngine = null; // Fall back to Windows PowerShell
                            }
                        }
                    }
                }

                // Use PowerShell 7+ engine if available and configured
                Tracer.TraceInformation("*** ENHANCED ENGINE USAGE DEBUG ***");
                Tracer.TraceInformation("powershell-engine-is-null: {0}", powerShellEngine == null);
                Tracer.TraceInformation("should-use-powershell7-result: {0}", ShouldUsePowerShell7());
                
                if (powerShellEngine != null && ShouldUsePowerShell7())
                {
                    try
                    {
                        Tracer.TraceInformation("*** USING POWERSHELL 7+ ENGINE FOR SCRIPT EXECUTION ***");
                        Tracer.TraceInformation("engine-type: '{0}'", powerShellEngine.EngineType);
                        Tracer.TraceInformation("engine-is-initialized: {0}", powerShellEngine.IsInitialized);
                        Tracer.TraceInformation("impersonation-required: {0}", ShouldImpersonate());
                        Tracer.TraceInformation("powershell7-execution-context: {0}", ShouldImpersonate() ? "ERROR: Should not reach here with impersonation" : "Non-impersonated execution (SAFE)");
                        powerShellEngine.OpenRunspace();
                        return powerShellEngine.InvokePowerShellScript(command, pipelineInput);
                    }
                    catch (PowerShell7ImpersonationException ps7ImpEx) when (ps7ImpEx.ShouldFallbackToWindowsPowerShell)
                    {
                        Tracer.TraceWarning("powershell7-impersonation-incompatible-falling-back-to-windows-powershell", 1, ps7ImpEx.Message);
                        
                        // Clean up the failed PowerShell 7+ engine
                        try
                        {
                            powerShellEngine.Dispose();
                        }
                        catch (Exception disposeEx)
                        {
                            Tracer.TraceWarning("failed-to-dispose-powershell7-engine", 1, disposeEx.Message);
                        }
                        powerShellEngine = null;
                        
                        // Log the fallback reason and continue to Windows PowerShell 5.1 execution
                        Tracer.TraceInformation("*** POWERSHELL 7 IMPERSONATION FALLBACK ***");
                        Tracer.TraceInformation("falling-back-to-windows-powershell51-due-to-impersonation-incompatibility: {0}", ps7ImpEx.Message);
                        Tracer.TraceInformation("this-is-expected-behavior-powershell7-does-not-support-impersonation");
                        
                        // Continue execution with Windows PowerShell 5.1 (don't throw exception)
                        // The code will naturally fall through to the Windows PowerShell 5.1 execution block below
                    }
                    catch (Exception ex)
                    {
                        Tracer.TraceError("powershell7-execution-failed-falling-back-to-windows-powershell: {0}", ex.Message?.Replace("{", "{{").Replace("}", "}}"));
                        Tracer.TraceWarning("powershell7-fallback-reason: {0}", 1, ex.Message?.Replace("{", "{{").Replace("}", "}}"));
                        
                        // Clean up the failed PowerShell 7+ engine
                        try
                        {
                            powerShellEngine.Dispose();
                        }
                        catch (Exception disposeEx)
                        {
                            Tracer.TraceWarning("failed-to-dispose-powershell7-engine", 1, disposeEx.Message);
                        }
                        powerShellEngine = null;
                        
                        // Fall back to Windows PowerShell 5.1
                        Tracer.TraceInformation("falling-back-to-windows-powershell51-due-to-powershell7-failure");
                    }
                }
                
                // Windows PowerShell 5.1 execution (either by choice or fallback)
                Tracer.TraceInformation("*** WINDOWS POWERSHELL 5.1 EXECUTION DECISION ***");
                Tracer.TraceInformation("powershell7-engine-is-null: {0}", powerShellEngine == null);
                Tracer.TraceInformation("should-use-powershell7: {0}", ShouldUsePowerShell7());
                
                // Determine the specific reason for using Windows PowerShell 5.1
                string fallbackReason;
                bool isPowerShell7Configured = PowerShellVersion != null && PowerShellVersion.Contains("PowerShell 7");
                bool requiresImpersonation = ShouldImpersonate();
                
                if (powerShellEngine == null)
                {
                    fallbackReason = "PowerShell 7 engine is null (initialization failed)";
                }
                else if (!isPowerShell7Configured)
                {
                    fallbackReason = "Configuration set to Windows PowerShell 5.1";
                }
                else if (isPowerShell7Configured && requiresImpersonation)
                {
                    fallbackReason = "AUTOMATIC FALLBACK: PowerShell 7 configured but impersonation required (PowerShell 7 does not support impersonation)";
                }
                else
                {
                    fallbackReason = "Unknown reason";
                }
                
                Tracer.TraceInformation("reason-for-windows-ps: {0}", fallbackReason);
                
                if (powerShellEngine == null || !ShouldUsePowerShell7())
                {
                    // Fall back to traditional Windows PowerShell 5.1 implementation
                    // Set up impersonation for Windows PowerShell 5.1 only, with defensive handling
                    bool impersonationSetup = false;
                    try
                    {
                        SetupImpersonationToken();
                        impersonationSetup = true;
                    }
                    catch (Exception ex)
                    {
                        Tracer.TraceWarning("impersonation-setup-failed-continuing-as-sync-service-account", 1, ex.Message);
                        Tracer.TraceError("impersonation-setup-error-details", ex);
                        // Continue without impersonation - this allows configuration to work
                        // but may cause runtime issues if impersonation is actually required
                    }
                    
                    Tracer.TraceInformation("using-windows-powershell51-engine for script execution, impersonation-setup: {0}", impersonationSetup);
                    if (runspace == null)
                    {
                        OpenRunspace();
                    }

                    try
                    {
                        powershell.Streams.ClearStreams();
                        powershell.Commands.Clear();
                        powershell.Commands.AddCommand(command);
                        if (pipelineInput != null)
                        {
                            Tracer.TraceInformation("pipeline-object-count {0:n0}", pipelineInput.Count);
                        }
                        Tracer.TraceInformation("start-invoke-script {0}", command.CommandText);
                        powershell.Invoke(pipelineInput, results);
                        Tracer.TraceInformation("end-invoke-script {0}", command.CommandText);
                    }
                    catch (RuntimeException e)
                    {
                        Tracer.TraceError("script-invocation-error", e);
                        Tracer.TraceError("script-invocation-inner-exception", e.InnerException != null ? e.InnerException : e);
                        Tracer.TraceError("script-invocation-inner-exception-message", e.InnerException != null ? e.InnerException.Message : "n/a");
                        Tracer.TraceError("script-invocation-error-stacktrace", e.StackTrace);
                        throw;
                    }
                    finally
                    {
                        try
                        {
                            Tracer.TraceInformation("script-had-errors {0}", powershell.HadErrors);
                        }
                        catch (AppDomainUnloadedException)
                        {
                            // AppDomain is unloading, ignore error status check
                        }
                        catch (Exception ex)
                        {
                            try { Tracer.TraceWarning("script-error-check-exception", 1, ex.Message); } catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Tracer.TraceError("invokepowershellscript", ex);
                throw;
            }
            finally
            {
                // Only revert impersonation if we're using Windows PowerShell 5.1 (either by choice or fallback)
                // PowerShell 7+ out-of-process execution doesn't use impersonation tokens
                if (powerShellEngine == null || !ShouldUsePowerShell7())
                {
                    try
                    {
                        RevertImpersonation();
                    }
                    catch (Exception ex)
                    {
                        Tracer.TraceWarning("revert-impersonation-failed", 1, ex.Message);
                        // Don't fail the operation if impersonation revert fails
                    }
                }
                Tracer.Exit("invokepowershellscript");
            }
            return results;
        }

        bool ShouldUsePowerShell7()
        {
            return ShouldUsePowerShell7(true); // Allow PowerShell 7 for import/export operations
        }

        bool ShouldUsePowerShell7(bool allowForSchemaOperations)
        {
            // Schema operations should always use Windows PowerShell 5.1 for stability
            if (!allowForSchemaOperations)
            {
                Tracer.TraceInformation("schema-operation-using-windows-powershell51");
                return false;
            }

            // Check if PowerShell 7+ is configured
            bool isPowerShell7Configured = PowerShellVersion != null && PowerShellVersion.Contains("PowerShell 7");
            Tracer.TraceInformation("powershell7-configured: {0}, powershell-version-property: '{1}'", isPowerShell7Configured, PowerShellVersion ?? "(null)");
            
            // If PowerShell 7 is not configured, use Windows PowerShell 5.1
            if (!isPowerShell7Configured)
            {
                Tracer.TraceInformation("powershell7-not-configured-using-windows-powershell51");
                return false;
            }
            
            // HYBRID FALLBACK LOGIC: PowerShell 7 does not support impersonation
            // If impersonation is required, automatically fall back to Windows PowerShell 5.1
            bool requiresImpersonation = ShouldImpersonate();
            Tracer.TraceInformation("*** HYBRID ENGINE SELECTION LOGIC ***");
            Tracer.TraceInformation("powershell7-configured: {0}", isPowerShell7Configured);
            Tracer.TraceInformation("requires-impersonation: {0}", requiresImpersonation);
            
            if (requiresImpersonation)
            {
                Tracer.TraceInformation("powershell7-with-impersonation-not-supported-falling-back-to-windows-powershell51");
                Tracer.TraceWarning("automatic-fallback-powershell7-impersonation-unsupported", 1, 
                    "Impersonation with PowerShell 7 is not implemented. Automatically falling back to Windows PowerShell 5.1 for impersonated operations. " +
                    "WARNING: If your scripts contain PowerShell 7-specific syntax (ternary operators, null coalescing, etc.), they will fail in Windows PowerShell 5.1 with syntax errors.");
                return false; // Force fallback to Windows PowerShell 5.1
            }
            
            // PowerShell 7 is configured and no impersonation is required - safe to use PowerShell 7
            Tracer.TraceInformation("powershell7-safe-to-use-no-impersonation-required");
            
            // ENHANCED DEBUG: Detailed engine selection analysis
            Tracer.TraceInformation("*** ENHANCED ENGINE SELECTION DEBUG ***");
            Tracer.TraceInformation("powershell-version-is-null: {0}", PowerShellVersion == null);
            Tracer.TraceInformation("powershell-version-exact-value: '{0}'", PowerShellVersion ?? "<NULL>");
            Tracer.TraceInformation("powershell-version-length: {0}", PowerShellVersion?.Length ?? -1);
            if (PowerShellVersion != null)
            {
                Tracer.TraceInformation("powershell-version-contains-ps7-check: '{0}' contains 'PowerShell 7' = {1}", PowerShellVersion, PowerShellVersion.Contains("PowerShell 7"));
                Tracer.TraceInformation("powershell-version-exact-match-check: '{0}' == 'PowerShell 7' = {1}", PowerShellVersion, PowerShellVersion == "PowerShell 7");
            }
            
            return true; // Use PowerShell 7 for non-impersonated operations
        }

        string GetPowerShell7Path()
        {
            // Use the configured PowerShell 7+ executable path
            return PowerShell7ExecutablePath ?? @"C:\Program Files\PowerShell\7\pwsh.exe";
        }

        void OpenRunspace()
        {
            Tracer.Enter("openrunspace");
            try
            {
                if (runspace == null)
                {
                    Tracer.TraceInformation("creating-runspace");
                    runspace = RunspaceFactory.CreateRunspace();
                    runspace.ApartmentState = System.Threading.ApartmentState.STA;
                    runspace.ThreadOptions = PSThreadOptions.Default;
                    runspace.StateChanged += Runspace_StateChanged;
                    runspace.AvailabilityChanged += Runspace_AvailabilityChanged;
                    Tracer.TraceInformation("created-runspace");
                }
                else
                {
                    try
                    {
                        Tracer.TraceInformation("existing-runspace-state '{0}'", runspace.RunspaceStateInfo.State);
                    }
                    catch (AppDomainUnloadedException)
                    {
                        // AppDomain is unloading, can't check runspace state
                    }
                }

                try
                {
                    if (runspace.RunspaceStateInfo.State == RunspaceState.BeforeOpen)
                    {
                        Tracer.TraceInformation("opening-runspace");
                        runspace.Open();
                    }
                    else
                    {
                        Tracer.TraceInformation("runspace-already-open");
                    }
                }
                catch (AppDomainUnloadedException)
                {
                    // AppDomain is unloading, skip runspace opening
                }

                try
                {
                    Tracer.TraceInformation("runspace-state '{0}'", runspace.RunspaceStateInfo.State);
                    if (runspace.RunspaceStateInfo.State == RunspaceState.Opened)
                    {
                        Tracer.TraceInformation("runspace-powershell-version {0}.{1}", runspace.Version.Major, runspace.Version.Minor);
                    }
                }
                catch (AppDomainUnloadedException)
                {
                    // AppDomain is unloading, skip runspace status checks
                }

                if (powershell == null)
                {
                    Tracer.TraceInformation("creating-powershell");
                    powershell = PowerShell.Create();
                    powershell.Runspace = runspace;
                    
                    try
                    {
                        Tracer.TraceInformation("powershell instanceid: {0}, runspace-id: {1}", powershell.InstanceId, powershell.Runspace.InstanceId);
                        Tracer.TraceInformation("powershell apartmentstate: {0}, version: {1}", powershell.Runspace.ApartmentState, powershell.Runspace.Version);
                    }
                    catch (AppDomainUnloadedException)
                    {
                        // AppDomain is unloading, skip diagnostic info
                    }

                    // the streams (Error, Debug, Progress, etc) are available on the PowerShell instance.
                    // we can review them during or after execution.
                    // we can also be notified when a new item is written to the stream (like this):
                    try
                    {
                        powershell.Streams.ClearStreams();
                        powershell.Streams.Error.DataAdded += Error_DataAdded;
                        powershell.Streams.Verbose.DataAdded += Verbose_DataAdded;
                        powershell.Streams.Warning.DataAdded += Warning_DataAdded;
                        powershell.Streams.Debug.DataAdded += Debug_DataAdded;
                        powershell.Streams.Progress.DataAdded += Progress_DataAdded;
                    }
                    catch (AppDomainUnloadedException)
                    {
                        // AppDomain is unloading, skip event handler setup
                    }
                    Tracer.TraceInformation("created-powershell");
                }
            }
            catch (Exception ex)
            {
                Tracer.TraceError("openrunspace", ex);
                throw;
            }
            finally
            {
                Tracer.Exit("openrunspace");
            }
        }

        void CloseRunspace()
        {
            Tracer.Enter("closerunspace");
            try
            {
                // Clean up PowerShell 7+ engine first if it was used
                if (powerShellEngine != null)
                {
                    try
                    {
                        Tracer.TraceInformation("disposing-powershell7-engine");
                        powerShellEngine.Dispose();
                        powerShellEngine = null;
                        Tracer.TraceInformation("disposed-powershell7-engine");
                    }
                    catch (AppDomainUnloadedException)
                    {
                        // AppDomain is unloading, just clear reference
                        powerShellEngine = null;
                    }
                    catch (Exception ex)
                    {
                        Tracer.TraceWarning("error-disposing-powershell7-engine", 1, ex.Message);
                        powerShellEngine = null;
                    }
                }

                if (powershell != null)
                {
                    try
                    {
                        Tracer.TraceInformation("disposing-powershell");
                        
                        // Detach event handlers first to prevent AppDomain exceptions
                        try
                        {
                            powershell.Streams.Error.DataAdded -= Error_DataAdded;
                            powershell.Streams.Verbose.DataAdded -= Verbose_DataAdded;
                            powershell.Streams.Warning.DataAdded -= Warning_DataAdded;
                            powershell.Streams.Debug.DataAdded -= Debug_DataAdded;
                            powershell.Streams.Progress.DataAdded -= Progress_DataAdded;
                        }
                        catch (AppDomainUnloadedException)
                        {
                            // AppDomain is unloading, event handler cleanup failed but continue
                        }
                        
                        powershell.Runspace.Close();
                        powershell.Dispose();
                        powershell = null;
                        Tracer.TraceInformation("disposed-powershell");
                    }
                    catch (AppDomainUnloadedException)
                    {
                        // AppDomain is unloading, just clear reference
                        powershell = null;
                    }
                    catch (Exception ex)
                    {
                        Tracer.TraceWarning("error-disposing-powershell", 1, ex.Message);
                        powershell = null;
                    }
                }
                
                if (runspace != null)
                {
                    try
                    {
                        bool runspaceIsClosed = false;
                        try
                        {
                            Tracer.TraceInformation("runspace-state '{0}'", runspace.RunspaceStateInfo.State);
                            runspaceIsClosed = (runspace.RunspaceStateInfo.State == RunspaceState.Closed);
                        }
                        catch (AppDomainUnloadedException)
                        {
                            // AppDomain is unloading, skip state check and assume not closed
                            runspaceIsClosed = false;
                        }
                        
                        if (!runspaceIsClosed)
                        {
                            try
                            {
                                Tracer.TraceInformation("removing-runspace-eventhandlers");
                                runspace.StateChanged -= Runspace_StateChanged;
                                runspace.AvailabilityChanged -= Runspace_AvailabilityChanged;
                                Tracer.TraceInformation("removed-runspace-eventhandlers");
                            }
                            catch (AppDomainUnloadedException)
                            {
                                // AppDomain is unloading, event handler cleanup failed but continue
                            }
                            
                            Tracer.TraceInformation("dispose-runspace");
                            runspace.Dispose(); // dispose also closes runspace
                            Tracer.TraceInformation("disposed-runspace");
                        }
                        runspace = null;
                    }
                    catch (AppDomainUnloadedException)
                    {
                        // AppDomain is unloading, just clear reference
                        runspace = null;
                    }
                    catch (Exception ex)
                    {
                        Tracer.TraceWarning("error-disposing-runspace", 1, ex.Message);
                        runspace = null;
                    }
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, cleanup what we can
                powershell = null;
                runspace = null;
                powerShellEngine = null;
            }
            catch (Exception ex)
            {
                Tracer.TraceError("closerunspace", ex);
                // Don't re-throw to allow graceful shutdown
            }
            finally
            {
                Tracer.Exit("closerunspace");
            }
        }

        // Helper methods to handle variables for both PowerShell engines
        void SetPowerShellVariable(string name, object value)
        {
            try
            {
                if (powerShellEngine != null && ShouldUsePowerShell7())
                {
                    Tracer.TraceInformation("setting-variable-powershell7 '{0}' = '{1}'", name, value);
                    powerShellEngine.SetVariable(name, value);
                }
                else if (runspace != null)
                {
                    Tracer.TraceInformation("setting-variable-windows-powershell '{0}' = '{1}'", name, value);
                    runspace.SessionStateProxy.SetVariable(name, value);
                }
                else
                {
                    Tracer.TraceWarning("unable-to-set-variable-no-engine-available '{0}'", 1, name);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, ignore variable operations
            }
            catch (Exception ex)
            {
                Tracer.TraceError("set-powershell-variable-error", ex);
                throw;
            }
        }

        object GetPowerShellVariable(string name)
        {
            try
            {
                if (powerShellEngine != null && ShouldUsePowerShell7())
                {
                    Tracer.TraceInformation("getting-variable-powershell7 '{0}'", name);
                    return powerShellEngine.GetVariable(name);
                }
                else if (runspace != null)
                {
                    Tracer.TraceInformation("getting-variable-windows-powershell '{0}'", name);
                    return runspace.SessionStateProxy.GetVariable(name);
                }
                else
                {
                    Tracer.TraceWarning("unable-to-get-variable-no-engine-available '{0}'", 1, name);
                    return null;
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, return null
                return null;
            }
            catch (Exception ex)
            {
                Tracer.TraceError("get-powershell-variable-error", ex);
                return null;
            }
        }

        // Event handlers for PowerShell 7+ engine
        void PowerShellEngine_Error(object sender, DataAddedEventArgs e)
        {
            try { Tracer.TraceError("powershell7-error: stream event"); }
            catch (AppDomainUnloadedException) { }
            catch { }
        }
        
        void PowerShellEngine_Verbose(object sender, DataAddedEventArgs e)
        {
            try { Tracer.TraceInformation("powershell7-verbose: stream event"); }
            catch (AppDomainUnloadedException) { }
            catch { }
        }
        
        void PowerShellEngine_Warning(object sender, DataAddedEventArgs e)
        {
            try { Tracer.TraceWarning("powershell7-warning: stream event", 1); }
            catch (AppDomainUnloadedException) { }
            catch { }
        }
        
        void PowerShellEngine_Debug(object sender, DataAddedEventArgs e)
        {
            try { Tracer.TraceInformation("powershell7-debug: stream event"); }
            catch (AppDomainUnloadedException) { }
            catch { }
        }
        
        void PowerShellEngine_Progress(object sender, DataAddedEventArgs e)
        {
            try { Tracer.TraceInformation("powershell7-progress: stream event"); }
            catch (AppDomainUnloadedException) { }
            catch { }
        }
    }
}
