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

        // Read by PSEngine's Process.Exited guard to short-circuit logging
        // once teardown has begun. Set via Interlocked in Dispose(bool).
        protected internal int _disposed;

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

                    // Do NOT terminate the run on non-terminating errors in ps.Streams.Error.
                    // Terminating errors (parse failures, `throw`, etc.) are already raised by
                    // ps.Invoke() and caught by the surrounding try/catch. Non-terminating errors
                    // (Write-Error, cmdlet non-terminating errors, parameter binding warnings) are
                    // logged via the Error event handler (see PSEngine.cs) and must not discard
                    // pipeline output - doing so loses every object the import script produced.
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

            // Treat strings as scalars (they are IEnumerable<char>) before the enumerable branch.
            if (value is string) return value;

            // PSObject wrapper: a PSCustomObject base (or self-referencing PSObject) carries
            // its data on the PSObject's Properties collection and is NOT [Serializable].
            // BinaryFormatter (used by ECMA2Host across its AppDomain boundary) will throw
            // SerializationException on it. Flatten such cases into a managed Hashtable.
            // Everything else can be unwrapped by recursing on BaseObject.
            if (value is PSObject pso)
            {
                if (pso.BaseObject is PSCustomObject || ReferenceEquals(pso.BaseObject, pso))
                {
                    return FlattenPSObjectProperties(pso);
                }
                return UnwrapValue(pso.BaseObject);
            }

            // Bare PSCustomObject (no enclosing PSObject) - defensive. Properties live on
            // the wrapping PSObject, so wrap-and-flatten.
            if (value is PSCustomObject)
            {
                return FlattenPSObjectProperties(new PSObject(value));
            }

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

        // Convert a PSObject (whose BaseObject is a PSCustomObject, or which has only
        // PowerShell-side note properties) into a serializable Hashtable. Recurses so
        // nested PSCustomObjects also flatten. This is what stops the
        // SerializationException ECMA2Host throws when marshalling import results
        // across its AppDomain via BinaryFormatter (PSCustomObject is not [Serializable]).
        private static Hashtable FlattenPSObjectProperties(PSObject pso)
        {
            var ht = new Hashtable();
            if (pso?.Properties == null) return ht;

            foreach (var prop in pso.Properties)
            {
                try
                {
                    ht[prop.Name] = UnwrapValue(prop.Value);
                }
                catch
                {
                    // Skip properties that throw on access (rare; deserialized PSObject
                    // property getters can fail for partially-resolved types).
                }
            }
            return ht;
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

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposing) return;
            if (System.Threading.Interlocked.Exchange(ref _disposed, 1) != 0) return;

            // 1. Stop receiving stream events so handlers don't race against teardown
            //    or hold AppDomain-rooted references during unload.
            Warning = null;
            Error = null;
            Verbose = null;
            Progress = null;
            Debug = null;

            // 2. Kill the child pwsh.exe FIRST. Closing the child closes its stdout
            //    pipe, which unblocks the PSRP OutOfProcessClientSessionTransportManager
            //    reader thread that is otherwise stuck in unmanaged ReadFile and cannot
            //    be aborted by AppDomain.Unload() (this is what surfaces in ECMA2Host
            //    as CannotUnloadAppDomainException / HRESULT 0x80131015).
            System.Diagnostics.Process child = null;
            try { child = _psProc?.Process; } catch { }

            if (child != null)
            {
                try { if (!child.HasExited) child.Kill(); } catch { }
                // 5s ceiling. Originally tightened to 1s as a perf tweak, but Windows
                // PowerShell 5.1's powershell.exe child (more in-process state than
                // pwsh 7's apphost) can need longer than 1s to release pipe handles
                // after Kill(). If the pipe is still open when we proceed to
                // runspace.Dispose() the host-side PSRP reader thread remains blocked
                // in unmanaged ReadFile and the ECMA2Host AppDomain unload fails with
                // CannotUnloadAppDomainException (0x80131015). On the happy path
                // (child exits promptly) WaitForExit returns immediately and the 5s
                // ceiling never engages, so this is correctness, not a perf regression.
                try { child.WaitForExit(5000); } catch { }
            }

            // 3. NOW dispose the runspace. With the child dead the graceful-close
            //    path short-circuits instead of blocking on a PSRP ack that will
            //    never arrive; the SDK's internal reader-thread join completes
            //    immediately because the pipe is at EOF.
            try { _runspace?.Dispose(); } catch { }
            _runspace = null;

            // 4. Dispose the process wrapper.
            try { _psProc?.Dispose(); } catch { }
            _psProc = null;

            // 5. Drain pending finalizers on the disposing thread so nothing from
            //    this engine is still awaiting collection when ECMA2Host attempts
            //    AppDomain.Unload().
            try
            {
                System.GC.Collect();
                System.GC.WaitForPendingFinalizers();
                System.GC.Collect();
            }
            catch { }
        }
    }

}