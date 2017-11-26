using Microsoft.MetadirectoryServices;
using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Principal;

namespace Granfeldt
{
	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
		Runspace runspace = null;
		PowerShell powershell = null;

		void results_DataAdded(object sender, DataAddedEventArgs e)
		{
			PSDataCollection<PSObject> obj = (PSDataCollection<PSObject>)sender;
			Tracer.TraceInformation("output-psdata-type {0}, {1}", e.Index, obj[e.Index].BaseObject.GetType());
		}
		static void Error_DataAdded(object sender, DataAddedEventArgs e)
		{
			PSDataCollection<ErrorRecord> err = (PSDataCollection<ErrorRecord>)sender;
			Tracer.TraceError("error id: {0}, message: {1}", err[e.Index].Exception == null ? -1 : err[e.Index].Exception.HResult, err[e.Index].FullyQualifiedErrorId, err[e.Index].ToString());
		}
		static void Verbose_DataAdded(object sender, DataAddedEventArgs e)
		{
			Tracer.TraceInformation("verbose {0}", ((PSDataCollection<VerboseRecord>)sender)[e.Index].ToString());
		}
		static void Warning_DataAdded(object sender, DataAddedEventArgs e)
		{
			Tracer.TraceWarning("warning {0}", ((PSDataCollection<WarningRecord>)sender)[e.Index].ToString());
		}
		static void Debug_DataAdded(object sender, DataAddedEventArgs e)
		{
			Tracer.TraceInformation("debug {0}", ((PSDataCollection<DebugRecord>)sender)[e.Index].ToString());
		}
		static void Progress_DataAdded(object sender, DataAddedEventArgs e)
		{
			Tracer.TraceInformation("progress {0}", ((PSDataCollection<ProgressRecord>)sender)[e.Index].ToString());
		}

		Collection<PSObject> InvokePowerShellScript(Command command, PSDataCollection<PSObject> pipelineInput)
		{
			Tracer.Enter("invokepowershellscript");
			SetupImpersonationToken();

			Collection<PSObject> results = new Collection<PSObject>();
			try
			{
				try
				{
					powershell.Streams.ClearStreams();
					powershell.Commands.Clear();
					powershell.Commands.AddCommand(command);

					if (pipelineInput != null)
					{
						Tracer.TraceInformation("pipeline-object-count {0:n0}", pipelineInput.Count);
					}
					//if (ShouldImpersonate())
					//{
					//	using (WindowsIdentity.Impersonate(impersonationToken))
					//	{
					//		Tracer.TraceInformation("start-invoke-script {0}", command.CommandText);
					//		if (pipelineInput != null)
					//		{
					//			powershell.Invoke(pipelineInput, results);
					//		}
					//		else
					//		{
					//			powershell.Invoke(null, results);
					//		}
					//	}
					//}
					//else
					//{

					Tracer.TraceInformation("start-invoke-script {0}", command.CommandText);
					if (pipelineInput != null)
					{
						powershell.Invoke(pipelineInput, results);
					}
					else
					{
						powershell.Invoke(null, results);
					}
					//}
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
					Tracer.TraceInformation("script-had-errors {0}", powershell.HadErrors);
				}
			}
			catch (Exception ex)
			{
				Tracer.TraceError("invokepowershellscript", ex);
				throw;
			}
			finally
			{
				RevertImpersonation();
				Tracer.Exit("invokepowershellscript");
			}
			return results;
		}

		void OpenRunspace()
		{
			Tracer.Enter("openrunspace");
			Tracer.Indent();
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
					Tracer.TraceInformation("existing-runspace-state '{0}'", runspace.RunspaceStateInfo.State);
				}
				if (runspace.RunspaceStateInfo.State == RunspaceState.BeforeOpen)
				{
					Tracer.TraceInformation("opening-runspace");
					runspace.Open();
				}
				else
				{
					Tracer.TraceInformation("runspace-already-open");
				}
				Tracer.TraceInformation("runspace-state '{0}'", runspace.RunspaceStateInfo.State);
				if (runspace.RunspaceStateInfo.State == RunspaceState.Opened)
				{
					Tracer.TraceInformation("runspace-powershell-version {0}.{1}", runspace.Version.Major, runspace.Version.Minor);
				}

				if (powershell == null)
				{
					Tracer.TraceInformation("creating-powershell");
					powershell = PowerShell.Create();
					powershell.Runspace = runspace;

					Tracer.TraceInformation("powershell instanceid: {0}, runspace-id: {1}", powershell.InstanceId, powershell.Runspace.InstanceId);
					Tracer.TraceInformation("powershell apartmentstate: {0}, version: {1}", powershell.Runspace.ApartmentState, powershell.Runspace.Version);

					// the streams (Error, Debug, Progress, etc) are available on the PowerShell instance.
					// we can review them during or after execution.
					// we can also be notified when a new item is written to the stream (like this):
					powershell.Streams.ClearStreams();
					powershell.Streams.Error.DataAdded += new EventHandler<DataAddedEventArgs>(Error_DataAdded);
					powershell.Streams.Verbose.DataAdded += new EventHandler<DataAddedEventArgs>(Verbose_DataAdded);
					powershell.Streams.Warning.DataAdded += new EventHandler<DataAddedEventArgs>(Warning_DataAdded);
					powershell.Streams.Debug.DataAdded += new EventHandler<DataAddedEventArgs>(Debug_DataAdded);
					powershell.Streams.Progress.DataAdded += new EventHandler<DataAddedEventArgs>(Progress_DataAdded);

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
				Tracer.Unindent();
				Tracer.Exit("openrunspace");
			}
		}

		void Runspace_AvailabilityChanged(object sender, RunspaceAvailabilityEventArgs e)
		{
			Tracer.TraceInformation("runspace-availability {0}", e.RunspaceAvailability);
		}

		void Runspace_StateChanged(object sender, RunspaceStateEventArgs e)
		{
			Tracer.TraceInformation("runspace-state-changed-to {0}", e.RunspaceStateInfo.State);
		}
		void CloseRunspace()
		{
			Tracer.Enter("closerunspace");
			Tracer.Indent();
			try
			{
				if (powershell != null)
				{
					Tracer.TraceInformation("disposing-powershell");
					powershell.Runspace.Close();
					powershell.Dispose();
					Tracer.TraceInformation("disposed-powershell");
				}

				if (runspace != null)
				{
					Tracer.TraceInformation("runspace-state '{0}'", runspace.RunspaceStateInfo.State);
					if (runspace.RunspaceStateInfo.State != RunspaceState.Closed)
					{
						Tracer.TraceInformation("removing-runspace-eventhandlers");
						runspace.StateChanged -= Runspace_StateChanged;
						runspace.AvailabilityChanged -= Runspace_AvailabilityChanged;
						Tracer.TraceInformation("removed-runspace-eventhandlers");
						Tracer.TraceInformation("dispose-runspace");
						runspace.Dispose(); // dispose also closes runspace
						Tracer.TraceInformation("disposed-runspace");
					}
				}
			}
			catch (Exception ex)
			{
				Tracer.TraceError("closerunspace", ex);
				throw;
			}
			finally
			{
				Tracer.Unindent();
				Tracer.Exit("closerunspace");
			}
		}

	}
}
