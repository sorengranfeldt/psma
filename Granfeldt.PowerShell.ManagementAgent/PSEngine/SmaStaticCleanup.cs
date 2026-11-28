using System;
using System.Linq;
using System.Reflection;

namespace Granfeldt
{
    /// <summary>
    /// Unregisters the Windows PowerShell 5.1 ETW provider that System.Management.Automation
    /// registers once per AppDomain, so the registration is freed deterministically on the
    /// connector-operation close path instead of leaking.
    ///
    /// ECMA2Host runs every connector operation in a short-lived AppDomain and unloads it
    /// afterwards. Opening the out-of-process runspace forces the WinPS 5.1 PSEtwLog type
    /// initializer, which calls EventProvider.EtwRegister() once per AppDomain and holds the
    /// registration in a private static field (PSEtwLogProvider.etwProvider). That registration
    /// is released only by the EventProvider finalizer, which runs only on a clean AppDomain
    /// unload. When an unload fails (CannotUnloadAppDomainException / HRESULT 0x80131015) the
    /// registration leaks. Windows caps ETW provider registrations at 1024 per process, so after
    /// enough leaked registrations every subsequent EtwRegister() fails with "Not enough memory
    /// resources are available to complete this operation", which fails PSEtwLog's static
    /// constructor, RemoteRunspace..ctor and therefore every import/export across all connectors.
    ///
    /// Disposing the static EventProvider (which calls EventUnregister) from PSEngineBase.Dispose,
    /// before the domain is torn down, frees the registration regardless of whether the later
    /// AppDomain unload succeeds. It runs once on the deterministic close thread and does NO work
    /// during the unload window itself.
    ///
    /// NOTE: an earlier revision (6.1.1029.2026) also hooked AppDomain.DomainUnload as a backstop
    /// and called AmsiUtils.Uninitialize() for a parallel per-AppDomain AMSI-context leak. Running
    /// that native cleanup inside the unload window - and a second AMSI uninitialize that collided
    /// with AMSI's own unload hook - pushed the unload of large imports past ECMAProxy's tolerance
    /// and caused CannotUnloadAppDomainException (0x80131015), failing the whole Full Import and
    /// discarding its objects (e.g. RapidGlobal, ~23k, PowerShell 7, paged). Both were removed: the
    /// ETW registration (the only hard, per-process cap) is freed here on close, and the AMSI
    /// context - which has no such cap - is left to AMSI's own unload cleanup.
    ///
    /// Everything is done by reflection so this assembly never takes a hard dependency on
    /// internal SMA types, and so the JIT never loads SMA into an AppDomain that never used it.
    /// The leaking type always lives in the in-box WinPS 5.1 assembly loaded into the .NET
    /// Framework host, independent of whether the connector runs scripts under PowerShell 7 or
    /// Windows PowerShell 5.1: that choice only changes which child process hosts the runspace
    /// server; the client-side PSEtwLog / RemoteRunspace in the host are always WinPS 5.1. So a
    /// single host-side cleanup covers PS7-only, WinPS 5.1-only and mixed connectors.
    /// </summary>
    internal static class SmaStaticCleanup
    {
        private const string SmaSimpleName = "System.Management.Automation";

        // Per-AppDomain guard (statics are per-domain). ECMA2Host uses one domain per operation,
        // so ReleaseAll is normally called once anyway; this keeps a repeat call a cheap no-op.
        private static bool _etwReleased;

        /// <summary>
        /// Releases the AppDomain-scoped WinPS 5.1 static state that must be freed deterministically
        /// on the close path - currently just the ETW provider registration. Never throws, and does
        /// no work during the AppDomain unload window.
        /// </summary>
        internal static void ReleaseAll()
        {
            ReleaseEtwProvider();
        }

        private static Assembly[] LoadedSma()
        {
            try
            {
                return AppDomain.CurrentDomain.GetAssemblies()
                    .Where(a =>
                    {
                        try { return string.Equals(a.GetName().Name, SmaSimpleName, StringComparison.OrdinalIgnoreCase); }
                        catch { return false; }
                    })
                    .ToArray();
            }
            catch
            {
                return new Assembly[0];
            }
        }

        /// <summary>
        /// Disposes PSEtwLogProvider.etwProvider (an EventProvider), which calls EventUnregister
        /// and frees this AppDomain's ETW provider registration. This is the fix for the
        /// 1024-registration-per-process exhaustion. No-op if SMA is not loaded or the provider
        /// was never created in this domain. Disposing is safe and idempotent: EventProvider.Dispose
        /// zeroes the registration handle, so subsequent writes silently no-op and a second Dispose
        /// does nothing.
        /// </summary>
        internal static void ReleaseEtwProvider()
        {
            if (_etwReleased) return;
            foreach (var sma in LoadedSma())
            {
                try
                {
                    var provType = sma.GetType("System.Management.Automation.Tracing.PSEtwLogProvider", false);
                    if (provType == null) continue;

                    var field = provType.GetField("etwProvider", BindingFlags.NonPublic | BindingFlags.Static);
                    if (field == null) continue;

                    var disposed = false;
                    if (field.GetValue(null) is IDisposable provider)
                    {
                        provider.Dispose();
                        disposed = true;
                    }
                    Tracer.TraceInformation("etw-provider-release disposed={0}", disposed);
                }
                catch (Exception ex)
                {
                    Tracer.TraceWarning("etw-provider-release-failed {0}", 1, ex.Message);
                }
            }
            _etwReleased = true;
        }
    }
}
