// May 29, 2012 | Søren Granfeldt
//  - project started
// May 29, 2012 | Søren Granfeldt
//  - fixed bug on import for multivalues
// September 7, 2012 | Søren Granfeldt
//  - added support for delta imports
//  - change Exception handling for ExportEntries from ExtensionException to EntryExportException
//  - added support for debug file through setting registry key (DebugLogFilename)
//    with date format string replacement
// September 10, 2012 | Søren Granfeldt
//  - added error handling for parameters (checking for file existence of scripts)
// September 11, 2012 | Søren Granfeldt
//  - fixed bug for error handling of configuration parameters (needed the page type if/else)
// September 12, 2012 | Søren Granfeldt
//  - added additional check for import object type in order to skip objects that are not hashtables
//  - more information on exceptions here - http://msdn.microsoft.com/en-us/library/hh859562%28v=vs.100%29
// September 14, 2012 | Søren Granfeldt
//  - added extra check to remove 'changeType' value from non-delete imported objects
// September 19, 2012 | Søren Granfeldt
//  - fixed bug on anchor text replace (code changed to use regex)
// September 19, 2012 | Søren Granfeldt
//  - added check for missing anchor on schema import
// October 13, 2012 | Søren Granfeldt
//  - added option for writing to event log on exceptions
// October 14, 2012 | Søren Granfeldt
//  - added section specific error codes on exceptions
//  - added UTC timestamp to log entries.
// October 14, 2012 | Søren Granfeldt
//  - added expiration timebomb for betaversions
// November 1, 2012 | Søren Granfeldt
//  - changed reference to R1 of Microsoft.MetadirectoryServiceEx
// November 5, 2012 | Søren Granfeldt
//  - added check for missing objectClass in schema
// November 5, 2012 | Søren Granfeldt
//  - added check for null values on imported object values
//  - added additional logging on missing objectclass
//  - added check for null values
// February 26, 2013 | Søren Granfeldt
//  - changed capabilities / DistinguishedNameStyle from None to Generic to allow for custom DN's to be returned
//  - added support for custom import/export ErrorName and ErrorDetail
//  - removed StackTrace names from logging (except for Enter/Leave)
// February 27, 2013 | Søren Granfeldt
//  - expanded check for invalid objects (non-hashtables) in pipeline
//  - added option to export simple (PSCustomObject) objects to export script instead of CSEntryChange
//  - added support for password management
//  - deprecated begin and end export scripts
// February 27, 2013 | Søren Granfeldt
//  - fixed bug with open runspace (needed ref)
//  - raised version to 4.5.0.1
// April 22, 2013 | Søren Granfeldt
//  - added better check for multivalues (support for binary, i.e. picture)
//  - raised version to 4.5.0.2
// May 8, 2013 | Søren Granfeldt
//  - fix regex bug for finding control attributes
// June 21, 2013 | Søren Granfeldt
//  - added robustness around invalid attribute names not in schema for objectclass
//  - changed type from string to object for customdata
// June 25, 2013 | Søren Granfeldt
//  - added schema property to pscustomobject exported as simple object
// June 26, 2013 | Søren Granfeldt
//  - raised version level to 4.6
// June 29, 2013 | Søren Granfeldt
//  - removed constraint for anchor to be of type string
// march 19, 2015 | Søren Granfeldt
//  - changed logging to use traceevent
//  - made OpenRunSpace more generic and removed duplicate instantiation of runspace
//  - moved instantiation of runspace to OpenRunSpace
// may 19, 2015 | Søren Granfeldt
//	- added explicit call to GC.Collection in CloseRunspace
//	- added removal of event handlers to prevent memory leak
// sep 30, 2015 | Søren Granfeldt
//	- removed option to use logging to file
//	- added setting moretoimport to false to prevent unwanted loops (if that was the problem)
//	- added calls to dispose in all close entry points for memory leak handling
// sep 30, 2015 | Søren Granfeldt
//	- added ExportType parameter when calling export script to support Full/Delta exports better
//	- moved InvokePipeline to generic function
// nov 05, 2015 | Søren Granfeldt
//	- added support for write-debug/progress/verbose/error in scripts
//	- changed Trace to use Tracer static class
//	- changed powershell to use PowerShell object to handle runspace memoryleak
//	- optimized import object conversion and added support for ignorecase on reserved attributes
//	- added parameter Credentials (as PSCredentials) to all scripts
//	- added paging support for converting objects to csentrychanges; should give more responsive ma
//	- simplified logging on import objects
// nov 20, 2015 | soren granfeldt
//	- removed default values for scripts
//	- added check for null securestring before building PSCredentials for scripts
// july 5, 2018 | soren granfeldt
//  - removed indent and unindent from tracer
//  - removed erroneous message about paged import not supported
//  - added schema (as psobject) as parameter to import and export scripts
//  - upped version to 5.5.3.1309
// march 27, 2021 | soren granfeldt
//	- added aux credentials set for scripts
//	- added support for configuration parameters
//	- merged try/catch pull request (#18 Added a try catch to the resolving of group names)
//	- upped version to 5.6.3.2021
// march 31, 2021 | Darren J Robinson
//	- fixed script parameter ($User => $Username)
//	- fixed MA Type so PSMA can update historical MA's
// january 3, 2022 | Benoit Boudeville
//	- added ImportOnly/ExportOnly specifiers for schema attributes
//	- upped to 5.6.4.2022
// Information on assembly version numbers - http://support.microsoft.com/kb/556041

using Microsoft.MetadirectoryServices;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;

namespace Granfeldt
{
	static class Constants
	{
		public static class Parameters
		{
			public static string Username = "Username";
			public static string Password = "Password";

			public static string UsernameAux = "Username (auxiliary)";
			public static string PasswordAux = "Password (auxiliary)";

			public static string ConfigurationParameters = "Configuration parameters";

			public static string ImpersonationDomain = "Domain (impersonate)";
			public static string ImpersonationUsername = "Username (impersonate)";
			public static string ImpersonationPassword = "Password  (impersonate)";

			public static string SchemaScript = "Schema Script";
			public static string ImportScript = "Import Script";
			public static string UsePagedImport = "Use paged import";
			public static string ExportScript = "Export Script";
			public static string ExportSimpleObjects = "Export simple objects";
			public static string PasswordManagementScript = "Password Management Script";
		}
		public static class ControlValues
		{
			public static string Identifier = "[Identifier]";
			public static string IdentifierAsGuid = "[IdentifierAsGuid]";
			public static string ErrorName = "[ErrorName]";
			public static string ErrorDetail = "[ErrorDetail]";
			public static string Anchor = "[Anchor]";
			public static string DN = "[DN]";
			public static string RDN = "[RDN]";
			public static string ObjectType = "[ObjectType]";
			public static string ObjectModificationType = "[ObjectModificationType]";
			public static string AttributeNames = "[AttributeNames]";
			public static string ChangedAttributeNames = "[ChangedAttributeNames]";
			public static string ObjectClass = "objectClass";
			public static string ChangeType = "changeType";
			public static string ObjectClassEx = "[ObjectClass]";
			public static string ChangeTypeEx = "[ChangeType]";
		}
	}

	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
		// New-EventLog -Source "PowerShell Management Agent" -LogName Application
		const string EventLogSource = "PowerShell Management Agent";
		const string EventLogName = "Application";

		string impersonationUserDomain;
		string impersonationUsername;
		string impersonationUserPassword;

		string Username;
		string Password;
		SecureString SecureStringPassword = null;

		string UsernameAux;
		string PasswordAux;
		SecureString SecureStringPasswordAux = null;

		Dictionary<string, string> ConfigurationParameter = new Dictionary<string, string>();

		void WhoAmI()
		{
			Tracer.Enter("show-identity");
			try
			{
				using (WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent())
				{
					Tracer.TraceInformation("identity-name: {0}", currentIdentity.Name);
					Tracer.TraceInformation("identity-token: {0}", currentIdentity.Token);
					Tracer.TraceInformation("identity-user-value: {0}", currentIdentity.User.Value);
					if (currentIdentity.Actor != null)
					{
						Tracer.TraceInformation("identity-actor: {0}", currentIdentity.Actor.Name);
						Tracer.TraceInformation("identity-actor-auth-type: {0}", currentIdentity.Actor.AuthenticationType);
					}
					if (currentIdentity.Groups != null)
					{
						foreach (IdentityReference group in currentIdentity.Groups)
						{
							try
							{
								NTAccount account = group.Translate(typeof(NTAccount)) as NTAccount;
								Tracer.TraceInformation("group-membership {0}", account.Value);
							}
							catch (Exception ex)
                            {
								/*
								 * If the SID cannot be resolved, log the SID, but don't throw the exception.
								 * Throwing the exception kills the run profile, where the membership might be totally
								 * irrelevant. We do log the SID for diagnostic purpose.
								 */
								Tracer.TraceError($"error-resolving-current-group-name: {group.Value}", ex);
							}
						}
					}
				}
			}
			catch (Exception ex)
			{
				Tracer.TraceError("error-showing-current-identity", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("show-identity");
			}
		}

		PSCredential GetSecureCredentials(string username, SecureString secureStringPassword)
		{
			if (string.IsNullOrEmpty(username) || (secureStringPassword == null))
			{
				Tracer.TraceInformation("username-or-password-empty returning-null-pscredentials");
				return null;
			}
			return new PSCredential(username, secureStringPassword);
		}


		public PowerShellManagementAgent()
		{
			Tracer.Enter("initialize");
			try
			{
				Tracer.TraceInformation("memory-usage {0:n} Mb", GC.GetTotalMemory(true) / 102400);
				System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
				FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
				string version = fvi.FileVersion;
				Tracer.TraceInformation("psma-version {0}", version);
				Tracer.TraceInformation("reading-registry-settings");
				RegistryKey machineRegistry = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
				RegistryKey mreRootKey = machineRegistry.OpenSubKey(@"SOFTWARE\Granfeldt\FIM\ManagementAgents\PowerShell", false);

				if (mreRootKey != null)
				{
					Tracer.TraceInformation("adding-eventlog-listener-for name: {0}, source: {1}", EventLogName, EventLogSource);
					EventLog evl = new EventLog(EventLogName);
					evl.Log = EventLogName;
					evl.Source = EventLogSource;

					EventLogTraceListener eventLog = new EventLogTraceListener(EventLogSource);
					eventLog.EventLog = evl;
					EventTypeFilter filter = new EventTypeFilter(SourceLevels.Warning | SourceLevels.Error | SourceLevels.Critical);
					eventLog.TraceOutputOptions = TraceOptions.Callstack;
					eventLog.Filter = filter;
					Tracer.trace.Listeners.Add(eventLog);
					if (!EventLog.SourceExists(EventLogSource))
					{
						Tracer.TraceInformation("creating-eventlog-source '{0}'", EventLogSource);
						EventLog.CreateEventSource(EventLogSource, EventLogName);
					}

					string logFileValue = mreRootKey.GetValue("DebugLogFileName", null) as string;
					if (logFileValue != null)
					{
						Tracer.TraceWarning("Logging to file is no longer supported. Please remove registrykey DebugLogFileName and use DebugView or similar instead to catch traces from this Management Agent");
					}
				}
			}
			catch (Exception ex)
			{
				Tracer.TraceError("could-not-initialize", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("initialize");
			}
		}

		public void Dispose()
		{
			Tracer.Enter("dispose");
			try
			{
				Tracer.TraceInformation("clearing-variables");
				csentryqueue = null;
				objectTypeAnchorAttributeNames = null;
				Tracer.TraceInformation("collection-garbage");
				GC.Collect(0, GCCollectionMode.Default, true);
			}
			catch (Exception ex)
			{
				Tracer.TraceError(ex.ToString());
				throw;
			}
			finally
			{
				Tracer.Exit("dispose");
			}
		}
	}
}
