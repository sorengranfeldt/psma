using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;

namespace Granfeldt
{
    public abstract class PSEngineBase : IPSEngine
    {
        protected Runspace _runspace;
        protected PowerShellProcessInstance _psProc;
        private bool _started;

        public event Action<string> Warning;
        public event Action<ErrorRecord> Error;
        public event Action<string> Verbose;
        public event Action<ProgressRecord> Progress;
        public event Action<DebugRecord> Debug;

        public string Domain = default;
        public string Username = default;
        public string Password = default;
        public SecureString SecurePassword => Password != null ? new System.Net.NetworkCredential("", Password).SecurePassword : null;

        public bool ShouldImpersonate() => !string.IsNullOrWhiteSpace(Username) && !string.IsNullOrEmpty(Password);
        public void SetImpersonation(string domain, string username, string password)
        {
            Domain = domain;
            Username = username;
            Password = password;
        }
        public void Start()
        {
            if (_started) return;
            (_runspace, _psProc) = CreateAndOpenRunspace();
            _started = true;
        }

        protected abstract (Runspace runspace, PowerShellProcessInstance proc) CreateAndOpenRunspace();

        public void SetVariable(string name, object value) => _runspace.SessionStateProxy.SetVariable(name, value);
        public object GetVariable(string name) => _runspace.SessionStateProxy.GetVariable(name);

        public Collection<PSObject> InvokeCommand(string commandName, IDictionary parameters = null, IEnumerable pipelineInput = null) => InvokeInternal(ps =>
        {
            ps.AddCommand(commandName);
            if (parameters != null) ps.AddParameters(parameters);
            Tracer.TraceInformation($"invoke-command: {commandName}");
        }, pipelineInput);

        public Collection<PSObject> InvokeScript(string scriptText, IDictionary parameters = null, IEnumerable pipelineInput = null) => InvokeInternal(ps =>
        {
            ps.AddScript(scriptText);
            if (parameters != null) ps.AddParameters(parameters);
        }, pipelineInput);

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
                        // no pipeline input -> invoke normally
                        result = ps.Invoke();
                    }
                    else
                    {
                        // feed objects into the *pipeline*, not as a single argument
                        var input = new PSDataCollection<object>();
                        foreach (var o in pipelineInput)
                        {
                            Tracer.TraceInformation("feeding object into pipeline: {0}", o?.ToString() ?? "<null>");
                            input.Add(o);
                        }
                        input.Complete(); // important: tells PowerShell no more input is coming

                        result = ps.Invoke(input);
                    }

                    ThrowIfHadErrors(ps);
                    UnwrapPSObjectsInResults(result);
                    return result;
                }
                catch (Exception ex)
                {
                    throw new RuntimeException("Error during PowerShell invocation: " + ex.Message, ex);
                }
            }
        }

        // OOP runspaces deliver values through PSRP, which wraps array/collection elements
        // (and dictionary values that are reference types) in PSObject. The MA.Import path
        // reads pipeline objects whose BaseObject is a Hashtable and feeds those values
        // straight to the sync engine — which throws "unable to cast PSObject to System.String"
        // for a String[] attribute when the array elements are PSObject wrappers. Unwrap once
        // here so callers see plain .NET values regardless of transport.
        private static void UnwrapPSObjectsInResults(Collection<PSObject> results)
        {
            if (results == null) return;
            foreach (var pso in results)
            {
                if (pso?.BaseObject is Hashtable ht)
                {
                    UnwrapHashtableValues(ht);
                }
            }
        }

        private static void UnwrapHashtableValues(Hashtable ht)
        {
            var keys = new ArrayList(ht.Keys);
            foreach (var k in keys)
            {
                ht[k] = UnwrapValue(ht[k]);
            }
        }

        private static object UnwrapValue(object value)
        {
            if (value == null) return null;

            if (value is PSObject pso)
            {
                return UnwrapValue(pso.BaseObject);
            }

            // Treat strings as scalars (they are IEnumerable<char>).
            if (value is string) return value;

            // Nested dictionaries / hashtables: recurse into values, preserve container.
            if (value is IDictionary dict)
            {
                var keys = new ArrayList(dict.Keys);
                foreach (var k in keys)
                {
                    dict[k] = UnwrapValue(dict[k]);
                }
                return dict;
            }

            // Byte arrays are commonly used for binary attributes — preserve as-is.
            if (value is byte[]) return value;

            // Any other enumerable (PSObject[], object[], List<PSObject>, etc.):
            // materialise to object[] with each element unwrapped.
            if (value is IEnumerable enumerable)
            {
                var list = new List<object>();
                foreach (var item in enumerable)
                {
                    list.Add(UnwrapValue(item));
                }
                return list.ToArray();
            }

            return value;
        }

        private PowerShell CreatePsWithStreams()
        {
            try
            {
                var ps = PowerShell.Create();
                ps.Runspace = _runspace;

                ps.Streams.Warning.DataAdded += (s, e) => { try { Warning?.Invoke(ps.Streams.Warning[e.Index].Message); } catch { } };
                ps.Streams.Error.DataAdded += (s, e) => { try { Error?.Invoke(ps.Streams.Error[e.Index]); } catch { } };
                ps.Streams.Verbose.DataAdded += (s, e) => { try { Verbose?.Invoke(ps.Streams.Verbose[e.Index].Message); } catch { } };
                ps.Streams.Progress.DataAdded += (s, e) => { try { Progress?.Invoke(ps.Streams.Progress[e.Index]); } catch { } };
                ps.Streams.Debug.DataAdded += (s, e) => { try { Debug?.Invoke(ps.Streams.Debug[e.Index]); } catch { } };

                return ps;
            }
            catch (Exception ex)
            {
                throw new RuntimeException("Error creating PowerShell instance: " + ex.Message, ex);
            }
        }

        private static void ThrowIfHadErrors(PowerShell ps, bool ignoreIfStopped = false)
        {
            if (ignoreIfStopped && ps.HadErrors) return;
            if (ps.HadErrors) throw new Microsoft.MetadirectoryServices.TerminateRunException(ps.Streams.Error.First().ToString());
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposing) return;

            try { _runspace?.Dispose(); } catch { }

            try
            {
                if (_psProc?.Process != null && !_psProc.Process.HasExited)
                    _psProc.Process.Kill();
            }
            catch { }
            finally
            {
                try { _psProc?.Dispose(); } catch { }
            }
        }
    }

}