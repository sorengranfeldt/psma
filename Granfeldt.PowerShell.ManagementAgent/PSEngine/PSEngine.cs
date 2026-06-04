using System;
using System.IO;
using System.Management.Automation.Runspaces;

namespace Granfeldt
{
    public sealed class PSEngine : PSEngineBase
    {
        public string PwshPath { get; }
        PowerShellEngineVersion powerShellVersion = PowerShellEngineVersion.WindowsPowerShell51;

        public PSEngine(string pwshPath = @"C:\Program Files\PowerShell\7\pwsh.exe", PowerShellEngineVersion powerShellEngine = PowerShellEngineVersion.WindowsPowerShell51)
        {
            PwshPath = pwshPath;
            powerShellVersion = powerShellEngine;
        }

        protected override (Runspace runspace, PowerShellProcessInstance proc) CreateAndOpenRunspace()
        {
            Tracer.TraceInformation($"powershell-engine-configured: {powerShellVersion}");
            var pspi = new PowerShellProcessInstance();

            Warning += w => Tracer.TraceWarning("WARNING: {0}", -1, w);
            Error += w => Tracer.TraceError("ERROR: {0}", w);
            Verbose += w => Tracer.TraceInformation("VERBOSE: {0}", w);
            Progress += p => Tracer.TraceInformation("PROGRESS: {0}", p);
            Debug += d => Tracer.TraceInformation("DEBUG: {0}", d);

            var si = pspi.Process.StartInfo;

            if (powerShellVersion == PowerShellEngineVersion.PowerShell7)
            {
                if (!File.Exists(PwshPath)) throw new FileNotFoundException($"pwsh/powershell not found: {PwshPath}");
                si.FileName = PwshPath;
                si.Arguments = "-s -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass";

                // Skip startup chores that have no value for an OOP runspace driven by C#:
                //  - POWERSHELL_TELEMETRY_OPTOUT disables the anonymous startup telemetry call.
                //  - POWERSHELL_UPDATECHECK=Off skips the daily update check that fires async
                //    at startup (still costs some startup CPU and creates a state file).
                // Both are documented Microsoft env vars intended for automated host execution.
                si.EnvironmentVariables["POWERSHELL_TELEMETRY_OPTOUT"] = "1";
                si.EnvironmentVariables["POWERSHELL_UPDATECHECK"] = "Off";
            }

            si.UseShellExecute = false;
            si.RedirectStandardOutput = true;
            si.RedirectStandardError = true;
            si.CreateNoWindow = true;
            // Always load the user profile. We previously tried setting this to
            // ShouldImpersonate() to save 200-500ms per spawn in the non-impersonated
            // case, but that broke Windows PowerShell 5.1 child startup: without the
            // profile loaded the child's %TEMP%, %APPDATA% and related paths fall back
            // to locations the service account can't always write to, causing Add-Type
            // (which compiles C# to a temp DLL) and module-cache paths to silently
            // fail. powershell.exe 5.1 depends on profile-loaded state in ways that
            // pwsh.exe 7 does not, so the perf optimisation is incompatible with the
            // export-engine-override feature. Keeping the original behaviour.
            si.LoadUserProfile = true;

            // impersonation credentials
            if (ShouldImpersonate())
            {
                si.Domain = string.IsNullOrWhiteSpace(Domain) ? "." : Domain;
                si.UserName = Username;
                si.Password = SecurePassword;
                Tracer.TraceInformation($"powershell-impersonation: domain='{si.Domain ?? "empty"}', username='{si.UserName ?? "(empty)"}', password={(si.Password == null ? "(empty)" : "***")}");

                // could be simplified since we already handled missing domain in si.Domain above
                // note that if using a local account for impersonation, Domain must be computername and not "."
                var acct = Domain + "\\" + Username;

                // give that account access to Session 0 window station & desktop
                WinStaDesktopAcl.GrantTo(acct);
            }
            Tracer.TraceInformation($"powershell-executable: '{si.FileName}', working-directory: {si.WorkingDirectory}, args: {si.Arguments}");

            pspi.Process.Exited += (s, e) =>
            {
                // Short-circuit if Dispose has begun - this callback fires on a
                // ThreadPool thread after Process.Kill in Dispose, and ECMA2Host
                // may already be unloading the AppDomain by the time it lands.
                if (System.Threading.Volatile.Read(ref _disposed) != 0) return;
                try { Tracer.TraceInformation($"powershell-exited. hasexited={pspi.Process.HasExited}, exitcode={pspi.Process.ExitCode:X8}, totaltime={pspi.Process.TotalProcessorTime}"); }
                catch { }
            };

            var runspace = RunspaceFactory.CreateOutOfProcessRunspace(new TypeTable(new string[0]), pspi);
            try
            {
                runspace.Open();
                return (runspace, pspi);
            }
            catch (Exception ex)
            {
                bool hasExited = false; int exitCode = 0;
                try { hasExited = pspi.Process.HasExited; exitCode = pspi.Process.ExitCode; } catch { }
                Tracer.TraceError($"powershell-runspace-open failed. hasexited={hasExited}, exitcode=0x{exitCode:X8}, exception: {ex}");
                throw;
            }
        }

    }
}
