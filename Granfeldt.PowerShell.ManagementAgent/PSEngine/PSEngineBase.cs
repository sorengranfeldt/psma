using Granfeldt;
using System;
using System.Collections;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Threading;
using System.Threading.Tasks;

public abstract class PSEngineBase : IPSEngine
{
    protected Runspace _runspace;
    protected PowerShellProcessInstance _psProc;
    private bool _started;

    public event Action<string> Warning;
    public event Action<ErrorRecord> Error;
    public event Action<string> Verbose;
    public event Action<ProgressRecord> Progress;

    public void OpenRunspace() { }
    public void CloseRunspace() { }
    public void Start()
    {
        if (_started) return;
        (_runspace, _psProc) = CreateAndOpenRunspace();
        _started = true;
    }

    protected abstract (Runspace runspace, PowerShellProcessInstance proc) CreateAndOpenRunspace();

    public void Bootstrap(string bootstrapScript)
    {
        if (string.IsNullOrWhiteSpace(bootstrapScript)) return;
        using (var ps = PowerShell.Create())
        {
            ps.Runspace = _runspace;
            ps.AddScript(bootstrapScript);
            ps.Invoke();
            ThrowIfHadErrors(ps);
        }
    }

    public void SetVariable(string name, object value) => _runspace.SessionStateProxy.SetVariable(name, value);
    public object GetVariable(string name) => _runspace.SessionStateProxy.GetVariable(name);

    public Collection<PSObject> InvokeCommand(string commandName, IDictionary parameters = null, IEnumerable pipelineInput = null) => InvokeInternal(ps =>
    {
        ps.AddCommand(commandName);
        if (parameters != null) ps.AddParameters(parameters);
        Tracer.TraceError($"invoke-command: {commandName}");
    }, pipelineInput);

    public Collection<PSObject> InvokeScript(string scriptText, IDictionary parameters = null, IEnumerable pipelineInput = null) => InvokeInternal(ps =>
    {
        ps.AddScript(scriptText);
        if (parameters != null) ps.AddParameters(parameters);
    }, pipelineInput);

    public async Task<PSDataCollection<PSObject>> InvokeScriptAsync(string scriptText, IDictionary parameters = null, IEnumerable pipelineInput = null, CancellationToken cancellationToken = default)
    {
        using (var ps = CreatePsWithStreams())
        {
            ps.AddScript(scriptText);
            if (parameters != null) ps.AddParameters(parameters);
            if (pipelineInput != null) ps.AddArgument(pipelineInput);

            using (cancellationToken.Register(() =>
            {
                try
                {
                    ps.Stop();
                }
                catch { }
            }))
            {
                var async = ps.BeginInvoke<PSObject, PSObject>(null, null);
                var result = await Task.Factory.FromAsync(async, ps.EndInvoke).ConfigureAwait(false);
                PumpStreams(ps);
                ThrowIfHadErrors(ps, ignoreIfStopped: cancellationToken.IsCancellationRequested);
                return result;
            }
        }
    }

    private Collection<PSObject> InvokeInternal(Action<PowerShell> addCommands, IEnumerable pipelineInput = null)
    {
        using (var ps = CreatePsWithStreams())
        {
            addCommands(ps);
            try
            {
                Collection<PSObject> result;

                if (pipelineInput is null)
                {
                    // No pipeline input -> invoke normally
                    result = ps.Invoke();
                }
                else
                {
                    // Feed objects into the *pipeline*, not as a single argument
                    var input = new PSDataCollection<object>();
                    foreach (var o in pipelineInput)
                        input.Add(o);
                    input.Complete(); // important: tells PowerShell no more input is coming

                    result = ps.Invoke(input);
                }

                PumpStreams(ps);
                ThrowIfHadErrors(ps);
                return result;
            }
            catch (Exception ex)
            {
                throw new RuntimeException("Error during PowerShell invocation: " + ex.Message, ex);
            }

        }
    }

    private PowerShell CreatePsWithStreams()
    {
        var ps = PowerShell.Create();
        ps.Runspace = _runspace;

        ps.Streams.Warning.DataAdded += (s, e) => { try { Warning?.Invoke(ps.Streams.Warning[e.Index].Message); } catch { } };
        ps.Streams.Error.DataAdded += (s, e) => { try { Error?.Invoke(ps.Streams.Error[e.Index]); } catch { } };
        ps.Streams.Verbose.DataAdded += (s, e) => { try { Verbose?.Invoke(ps.Streams.Verbose[e.Index].Message); } catch { } };
        ps.Streams.Progress.DataAdded += (s, e) => { try { Progress?.Invoke(ps.Streams.Progress[e.Index]); } catch { } };

        return ps;
    }

    private void PumpStreams(PowerShell ps)
    {
        foreach (var w in ps.Streams.Warning) Warning?.Invoke(w.Message);
        foreach (var v in ps.Streams.Verbose) Verbose?.Invoke(v.Message);
        foreach (var pr in ps.Streams.Progress) Progress?.Invoke(pr);
        foreach (var er in ps.Streams.Error) Error?.Invoke(er);
    }

    private static void ThrowIfHadErrors(PowerShell ps, bool ignoreIfStopped = false)
    {
        if (ignoreIfStopped && ps.HadErrors) return;
        if (ps.HadErrors) throw new RuntimeException(ps.Streams.Error.First().ToString());
    }

    public void Dispose()
    {
        try { _runspace?.Dispose(); } catch { }
        try
        {
            if (_psProc?.Process != null && !_psProc.Process.HasExited)
                _psProc.Process.Kill();
        }
        catch { }
        finally { try { _psProc?.Dispose(); } catch { } }
    }
}

