using Microsoft.MetadirectoryServices;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management.Automation;
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

            public static string PowerShellVersion = "PowerShell Version";
            public static string PowerShell7ExecutablePath = "PowerShell 7 Executable Path";
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
    public enum PowerShellEngineVersion { WindowsPowerShell51, PowerShell7 }
    public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
    {
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

        // Script file paths
        string schemaScriptPath = null;
        string importScriptPath = null;
        string exportScriptPath = null;
        string passwordManagementScriptPath = null;

        // Script execution options
        bool usePagedImport = false;
        bool exportSimpleObjects = true;

        PowerShellEngineVersion SelectedPowerShellEngine = PowerShellEngineVersion.WindowsPowerShell51;
        IPSEngine engine = default;

        [Obsolete] 
        string PowerShellVersion = "Windows PowerShell 5.1"; // Default to Windows PowerShell 5.1
        string PowerShell7ExecutablePath = @"C:\Program Files\PowerShell\7\pwsh.exe"; // Default PowerShell 7 path

        void EnsurePowerShellEngine()
        {
            if (engine == null)
            {
                engine = new PSEngine(PowerShell7ExecutablePath, SelectedPowerShellEngine);
            }
            engine.SetImpersonation(impersonationUserDomain, impersonationUsername, impersonationUserPassword);
            engine.Start();
        }

        Dictionary<string, object> GetDefaultScriptParameters()
        {
            return new Dictionary<string, object> 
                {
                    { "Username", Username },
                    { "Password", Password },
                    { "Credentials", GetSecureCredentials(Username, SecureStringPassword) },
                    { "AuxUsername", UsernameAux },
                    { "AuxPassword", PasswordAux },
                    { "AuxCredentials", GetSecureCredentials(UsernameAux, SecureStringPasswordAux) },
                    { "ImpersonationDomain", impersonationUserDomain },
                    { "ImpersonationUsername", impersonationUsername },
                    { "ImpersonationPassword", impersonationUserPassword },
                    { "ConfigurationParameter", ConfigurationParameter },
                };
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

            // Check if AppDomain is finalizing before doing any cleanup
            try
            {
                if (AppDomain.CurrentDomain.IsFinalizingForUnload())
                {
                    Tracer.TraceWarning("dispose-skipped-appdomain-finalizing", 1);
                    return;
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is already unloading, exit immediately
                Tracer.TraceWarning("dispose-aborted-appdomain-unloaded", 1);
                return;
            }

            try
            {
                try
                {
                    Tracer.TraceInformation("clearing-variables");
                    csentryqueue = null;
                    objectTypeAnchorAttributeNames = null;
                }
                catch (AppDomainUnloadedException)
                {
                    // AppDomain is unloading, ignore variable cleanup
                }

                try
                {
                    // Only perform garbage collection if we're not in an unloading AppDomain
                    // as this can trigger finalizers that access disposed PowerShell objects
                    Tracer.TraceInformation("checking-appdomain-state-before-gc");
                    if (!AppDomain.CurrentDomain.IsFinalizingForUnload())
                    {
                        Tracer.TraceInformation("collection-garbage");
                        GC.Collect(0, GCCollectionMode.Default, true);
                        Tracer.TraceInformation("garbage-collection-completed");
                    }
                    else
                    {
                        Tracer.TraceInformation("skipping-gc-appdomain-finalizing");
                    }
                }
                catch (AppDomainUnloadedException)
                {
                    // AppDomain is unloading, ignore garbage collection
                    Tracer.TraceInformation("gc-skipped-appdomain-unloading");
                }
                catch (Exception ex)
                {
                    // Don't let GC failures break disposal
                    Tracer.TraceWarning("gc-failed-but-continuing", 1, ex.Message);
                }
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, allow graceful exit
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
