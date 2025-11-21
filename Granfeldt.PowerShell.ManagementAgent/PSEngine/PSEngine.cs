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
            }

            si.UseShellExecute = false;
            si.RedirectStandardOutput = true;
            si.RedirectStandardError = true;
            si.CreateNoWindow = true;
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
