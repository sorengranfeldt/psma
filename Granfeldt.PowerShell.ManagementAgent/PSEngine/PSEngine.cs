using System;
using System.IO;
using System.Management.Automation;
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
            var smaAsm = typeof(System.Management.Automation.PowerShell).Assembly;
            Tracer.TraceInformation("Host SMA: {0} @ {1}", smaAsm.GetName().Version, smaAsm.Location);
            Tracer.TraceInformation("Host bitness: {0}-bit  OS: {1}", Environment.Is64BitProcess ? "64" : "32", Environment.OSVersion);

            Tracer.TraceInformation("Using-PSEngine: {0}", powerShellVersion.ToString());
            var pspi = new PowerShellProcessInstance();

            Warning += w => Tracer.TraceInformation("WARNING: {0}", w);
            Error += w => Tracer.TraceError("ERROR: {0}", w);
            Verbose += w => Tracer.TraceInformation("INFO: {0}", w);

            var si = pspi.Process.StartInfo;

            if (powerShellVersion == PowerShellEngineVersion.PowerShell7)
            {
                if (!System.IO.File.Exists(PwshPath)) throw new FileNotFoundException($"pwsh/powershell not found: {PwshPath}");
                si.FileName = PwshPath;
                si.Arguments = "-s -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass";
            }

            si.UseShellExecute = false;
            si.RedirectStandardOutput = true;
            si.RedirectStandardError = true;
            si.CreateNoWindow = true;
            si.LoadUserProfile = true;
            si.WorkingDirectory = Path.GetDirectoryName(PwshPath) ?? @"C:\Windows\System32";

            // Credentials
            if (ShouldImpersonate())
            {
                si.Domain = string.IsNullOrWhiteSpace(Domain) ? "." : Domain;
                si.UserName = Username;
                si.Password = SecurePassword;
                Tracer.TraceInformation($"Impersonation: Domain='{si.Domain ?? "empty"}', UserName='{si.UserName ?? "(empty)"}', Password={(si.Password == null ? "(empty)" : "***")}");

                // could be simplified since we already handled missing domain in si.Domain above
                // note that if using a local account for impersonation, Domain must be computername and not "."
                var acct = Domain + "\\" + Username;

                // give that account access to Session 0 window station & desktop
                WinStaDesktopAcl.GrantTo(acct);
            }

            // SHOULD WE DO A WHOAMI (from old impersonation) HERE TO LOG THE CONTEXT WE ARE RUNNING AS?

            Tracer.TraceInformation("using-exe: '{0}'  Exists={1}", si.FileName, System.IO.File.Exists(si.FileName));
            Tracer.TraceInformation("args: {0}", si.Arguments);
            Tracer.TraceInformation("WorkingDirectory: '{0}' Exists={1}", si.WorkingDirectory, Directory.Exists(si.WorkingDirectory));
            Tracer.TraceInformation("UseShellExecute={0}  LoadUserProfile={1}", si.UseShellExecute, si.LoadUserProfile);
            Tracer.TraceInformation("Env: SystemRoot='{0}', WINDIR='{1}', ComSpec='{2}', Path(empty)={3}",
                si.EnvironmentVariables["SystemRoot"], si.EnvironmentVariables["WINDIR"],
                si.EnvironmentVariables["ComSpec"], string.IsNullOrEmpty(si.EnvironmentVariables["Path"]));

            Tracer.TraceInformation("Env: TEMP='{0}', TMP='{1}', USERPROFILE='{2}', HOMEDRIVE='{3}', HOMEPATH='{4}'",
                si.EnvironmentVariables["TEMP"], si.EnvironmentVariables["TMP"],
                si.EnvironmentVariables["USERPROFILE"], si.EnvironmentVariables["HOMEDRIVE"], si.EnvironmentVariables["HOMEPATH"]);

            //pspi.Process.ErrorDataReceived += (s, e) => { if (e.Data != null) Tracer.TraceError("pwsh[stderr]: {0}", e.Data); };
            //pspi.Process.OutputDataReceived += (s, e) => { if (e.Data != null) Tracer.TraceInformation("pwsh[stdout]: {0}", e.Data); };
            //pspi.Process.EnableRaisingEvents = true;
            pspi.Process.Exited += (s, e) =>
            {
                try { Tracer.TraceError("pwsh exited. HasExited={0}, ExitCode={1:X8}", pspi.Process.HasExited, pspi.Process.ExitCode); }
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

                Tracer.TraceError("Runspace.Open failed. HasExited={0}, ExitCode=0x{1:X8}", hasExited, exitCode);
                Tracer.TraceError("FileName='{0}', WD='{1}'", si.FileName, si.WorkingDirectory);
                Tracer.TraceError("Env SystemRoot='{0}', TEMP='{1}', USERPROFILE='{2}'",
                    si.EnvironmentVariables["SystemRoot"], si.EnvironmentVariables["TEMP"], si.EnvironmentVariables["USERPROFILE"]);
                Tracer.TraceError("Exception: {0}", ex);
                Tracer.TraceError("BaseException: {0}", ex.GetBaseException());
                throw;
            }
        }

    }
}
