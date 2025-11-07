using System;
using System.Collections;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;

namespace Granfeldt
{
    public interface IPSEngine : IDisposable
    {
        void SetImpersonation(string domain, string username, string password);
        
        void Start();

        // Invoke arbitrary script text; returns pipeline PSObjects.
        Collection<PSObject> InvokeScript(string scriptText, IDictionary parameters = null, IEnumerable pipelineInput = null);

        // Invoke a command (function/cmdlet/script file) with named parameters.
        Collection<PSObject> InvokeCommand(string commandName, IDictionary parameters = null, IEnumerable pipelineInput = null);

        // Async flavor with cancellation (still returns PSObjects).
        Task<PSDataCollection<PSObject>> InvokeScriptAsync(string scriptText, IDictionary parameters = null, IEnumerable pipelineInput = null, CancellationToken cancellationToken = default);

        // Session state helpers (persist as long as runspace is open).
        void SetVariable(string name, object value);
        object GetVariable(string name);

        // One-time bootstrap for modules/functions/globals.
        void Bootstrap(string bootstrapScript);

        // Stream taps (PSRP streams, not text):
        event Action<string> Warning;
        event Action<ErrorRecord> Error;
        event Action<string> Verbose;
        event Action<ProgressRecord> Progress;
    }
}
