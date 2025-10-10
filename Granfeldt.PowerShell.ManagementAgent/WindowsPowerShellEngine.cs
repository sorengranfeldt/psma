using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Granfeldt
{
    /// <summary>
    /// PowerShell engine implementation for Windows PowerShell 5.1
    /// </summary>
    public class WindowsPowerShellEngine : IPowerShellEngine
    {
        private Runspace runspace = null;
        private PowerShell powershell = null;
        private bool disposed = false;

        public Version PowerShellVersion => runspace?.Version ?? new Version(5, 1);
        public string EngineType => "Windows PowerShell 5.1";
        public bool IsInitialized => runspace != null && powershell != null;

        public event EventHandler<DataAddedEventArgs> PowerShellError;
        public event EventHandler<DataAddedEventArgs> PowerShellVerbose;
        public event EventHandler<DataAddedEventArgs> PowerShellWarning;
        public event EventHandler<DataAddedEventArgs> PowerShellDebug;
        public event EventHandler<DataAddedEventArgs> PowerShellProgress;

        public void Initialize()
        {
            Tracer.TraceInformation("initializing-windows-powershell-engine");
            // Initialization logic if needed
        }

        public void OpenRunspace()
        {
            Tracer.Enter("openrunspace-windows-powershell");
            try
            {
                if (runspace == null)
                {
                    Tracer.TraceInformation("creating-windows-powershell-runspace");
                    runspace = RunspaceFactory.CreateRunspace();
                    // runspace.ApartmentState = System.Threading.ApartmentState.STA; // Not available in PowerShell Standard
                    runspace.ThreadOptions = PSThreadOptions.Default;
                    runspace.StateChanged += Runspace_StateChanged;
                    runspace.AvailabilityChanged += Runspace_AvailabilityChanged;
                    Tracer.TraceInformation("created-windows-powershell-runspace");
                }
                else
                {
                    Tracer.TraceInformation("existing-runspace-state '{0}'", runspace.RunspaceStateInfo.State);
                }

                if (runspace.RunspaceStateInfo.State == RunspaceState.BeforeOpen)
                {
                    Tracer.TraceInformation("opening-windows-powershell-runspace");
                    runspace.Open();
                }
                else
                {
                    Tracer.TraceInformation("windows-powershell-runspace-already-open");
                }

                Tracer.TraceInformation("windows-powershell-runspace-state '{0}'", runspace.RunspaceStateInfo.State);
                if (runspace.RunspaceStateInfo.State == RunspaceState.Opened)
                {
                    Tracer.TraceInformation("windows-powershell-version {0}.{1}", runspace.Version.Major, runspace.Version.Minor);
                }

                if (powershell == null)
                {
                    Tracer.TraceInformation("creating-windows-powershell-instance");
                    powershell = PowerShell.Create();
                    powershell.Runspace = runspace;

                    Tracer.TraceInformation("windows-powershell instanceid: {0}, runspace-id: {1}", powershell.InstanceId, powershell.Runspace.InstanceId);
                    Tracer.TraceInformation("windows-powershell version: {1}", powershell.Runspace.Version);

                    // Setup event handlers
                    powershell.Streams.ClearStreams();
                    powershell.Streams.Error.DataAdded += Error_DataAdded;
                    powershell.Streams.Verbose.DataAdded += Verbose_DataAdded;
                    powershell.Streams.Warning.DataAdded += Warning_DataAdded;
                    powershell.Streams.Debug.DataAdded += Debug_DataAdded;
                    powershell.Streams.Progress.DataAdded += Progress_DataAdded;

                    Tracer.TraceInformation("created-windows-powershell-instance");
                }
            }
            catch (Exception ex)
            {
                Tracer.TraceError("openrunspace-windows-powershell", ex);
                throw;
            }
            finally
            {
                Tracer.Exit("openrunspace-windows-powershell");
            }
        }

        public void CloseRunspace()
        {
            Tracer.Enter("closerunspace-windows-powershell");
            try
            {
                if (powershell != null)
                {
                    Tracer.TraceInformation("disposing-windows-powershell-instance");
                    powershell.Runspace.Close();
                    powershell.Dispose();
                    powershell = null;
                    Tracer.TraceInformation("disposed-windows-powershell-instance");
                }

                if (runspace != null)
                {
                    Tracer.TraceInformation("windows-powershell-runspace-state '{0}'", runspace.RunspaceStateInfo.State);
                    if (runspace.RunspaceStateInfo.State != RunspaceState.Closed)
                    {
                        Tracer.TraceInformation("removing-windows-powershell-runspace-eventhandlers");
                        runspace.StateChanged -= Runspace_StateChanged;
                        runspace.AvailabilityChanged -= Runspace_AvailabilityChanged;
                        Tracer.TraceInformation("removed-windows-powershell-runspace-eventhandlers");
                        Tracer.TraceInformation("dispose-windows-powershell-runspace");
                        runspace.Dispose(); // dispose also closes runspace
                        runspace = null;
                        Tracer.TraceInformation("disposed-windows-powershell-runspace");
                    }
                }
            }
            catch (Exception ex)
            {
                Tracer.TraceError("closerunspace-windows-powershell", ex);
                throw;
            }
            finally
            {
                Tracer.Exit("closerunspace-windows-powershell");
            }
        }

        public Collection<PSObject> InvokePowerShellScript(Command command, PSDataCollection<PSObject> pipelineInput)
        {
            Tracer.Enter("invokepowershellscript-windows-powershell");

            Collection<PSObject> results = new Collection<PSObject>();
            try
            {
                try
                {
                    powershell.Streams.ClearStreams();
                    powershell.Commands.Clear();
                    powershell.Commands.AddCommand(command);

                    // Add special variables to indicate we're using Windows PowerShell 5.1 engine
                    SetVariable("PSMAEngineType", "Windows PowerShell 5.1");
                    SetVariable("PSMAEngineVersion", "5.1");
                    SetVariable("PSMAEngineSelected", "Windows PowerShell 5.1");
                    SetVariable("PSMA_ENGINE", "Windows PowerShell 5.1");

                    if (pipelineInput != null)
                    {
                        Tracer.TraceInformation("windows-powershell-pipeline-object-count {0:n0}", pipelineInput.Count);
                    }

                    Tracer.TraceInformation("start-invoke-windows-powershell-script {0}", command.CommandText);
                    powershell.Invoke(pipelineInput, results);
                    Tracer.TraceInformation("end-invoke-windows-powershell-script {0}", command.CommandText);
                }
                catch (RuntimeException e)
                {
                    Tracer.TraceError("windows-powershell-script-invocation-error", e);
                    Tracer.TraceError("windows-powershell-script-invocation-inner-exception", e.InnerException != null ? e.InnerException : e);
                    Tracer.TraceError("windows-powershell-script-invocation-inner-exception-message", e.InnerException != null ? e.InnerException.Message : "n/a");
                    Tracer.TraceError("windows-powershell-script-invocation-error-stacktrace", e.StackTrace);
                    throw;
                }
                finally
                {
                    Tracer.TraceInformation("windows-powershell-script-had-errors {0}", powershell.HadErrors);
                }
            }
            catch (Exception ex)
            {
                Tracer.TraceError("invokepowershellscript-windows-powershell", ex);
                throw;
            }
            finally
            {
                Tracer.Exit("invokepowershellscript-windows-powershell");
            }
            return results;
        }

        public void SetVariable(string name, object value)
        {
            if (runspace?.SessionStateProxy != null)
            {
                runspace.SessionStateProxy.SetVariable(name, value);
            }
        }

        public object GetVariable(string name)
        {
            if (runspace?.SessionStateProxy != null)
            {
                return runspace.SessionStateProxy.GetVariable(name);
            }
            return null;
        }

        public void SetImpersonationCredentials(string username, string domain, string password)
        {
            // For Windows PowerShell 5.1, impersonation is handled by the main MA class
            // using Windows impersonation tokens. This method is a no-op for compatibility.
            Tracer.TraceInformation("impersonation-credentials-set-for-windows-powershell-handled-by-ma");
        }

        public bool IsImpersonationRequested()
        {
            // Windows PowerShell 5.1 doesn't track impersonation requests in the engine
            // Impersonation is handled by the main MA class
            return false;
        }

        private void Error_DataAdded(object sender, DataAddedEventArgs e)
        {
            PSDataCollection<ErrorRecord> err = (PSDataCollection<ErrorRecord>)sender;
            Tracer.TraceError("windows-powershell-error id: {0}, message: {1}", err[e.Index].Exception == null ? -1 : err[e.Index].Exception.HResult, err[e.Index].FullyQualifiedErrorId, err[e.Index].ToString());
            PowerShellError?.Invoke(sender, e);
        }

        private void Verbose_DataAdded(object sender, DataAddedEventArgs e)
        {
            Tracer.TraceInformation("windows-powershell-verbose {0}", ((PSDataCollection<VerboseRecord>)sender)[e.Index].ToString());
            PowerShellVerbose?.Invoke(sender, e);
        }

        private void Warning_DataAdded(object sender, DataAddedEventArgs e)
        {
            Tracer.TraceWarning("windows-powershell-warning {0}", 1, ((PSDataCollection<WarningRecord>)sender)[e.Index]);
            PowerShellWarning?.Invoke(sender, e);
        }

        private void Debug_DataAdded(object sender, DataAddedEventArgs e)
        {
            Tracer.TraceInformation("windows-powershell-debug {0}", ((PSDataCollection<DebugRecord>)sender)[e.Index].ToString());
            PowerShellDebug?.Invoke(sender, e);
        }

        private void Progress_DataAdded(object sender, DataAddedEventArgs e)
        {
            Tracer.TraceInformation("windows-powershell-progress {0}", ((PSDataCollection<ProgressRecord>)sender)[e.Index].ToString());
            PowerShellProgress?.Invoke(sender, e);
        }

        private void Runspace_AvailabilityChanged(object sender, RunspaceAvailabilityEventArgs e)
        {
            Tracer.TraceInformation("windows-powershell-runspace-availability {0}", e.RunspaceAvailability);
        }

        private void Runspace_StateChanged(object sender, RunspaceStateEventArgs e)
        {
            Tracer.TraceInformation("windows-powershell-runspace-state-changed-to {0}", e.RunspaceStateInfo.State);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    CloseRunspace();
                }
                disposed = true;
            }
        }
    }
}
