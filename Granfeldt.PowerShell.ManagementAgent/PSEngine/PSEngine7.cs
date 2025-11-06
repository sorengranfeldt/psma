using System;
using System.Diagnostics;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Security;

namespace Granfeldt
{
    public sealed class PSEnginePwsh7 : PSEngineBase
    {
        public string PwshPath { get; }
        public string ExtraArgs { get; }

        public PSEnginePwsh7(
            string pwshPath = @"C:\Program Files\PowerShell\7\pwsh.exe",
            string extraArgs = null)
        { PwshPath = pwshPath; ExtraArgs = extraArgs; }

        protected override (Runspace runspace, PowerShellProcessInstance proc) CreateAndOpenRunspace()
        {
            var pspi = new PowerShellProcessInstance();

            pspi.Process.StartInfo.FileName = PwshPath;

            pspi.Process.StartInfo.UseShellExecute = false;
            pspi.Process.StartInfo.RedirectStandardOutput = true;
            pspi.Process.StartInfo.RedirectStandardError = true;
            pspi.Process.StartInfo.CreateNoWindow = true;

            Tracer.TraceError("using-pwsh-executable-path: '{0}'", PwshPath);
            pspi.Process.StartInfo.Arguments = "-s -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass" + (string.IsNullOrWhiteSpace(ExtraArgs) ? "" : " " + ExtraArgs);

            //pspi.Process.StartInfo.Domain = ""; // if needed  
            //pspi.Process.StartInfo.UserName = "pstest";
            //SecureString theString = new NetworkCredential("", "test123").SecurePassword;
            //pspi.Process.StartInfo.Password = theString; // SecureString if needed

            //pspi.Process.Start();

            var typeTable = new TypeTable(Array.Empty<string>()); // or TypeTable.Empty in newer builds
            var runspace = RunspaceFactory.CreateOutOfProcessRunspace(typeTable, pspi);

            runspace.Open();
            return (runspace, pspi);
        }
    }
}
