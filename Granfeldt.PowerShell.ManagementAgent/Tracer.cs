using System;
using System.Diagnostics;
using System.Text;

namespace Granfeldt
{
    public static class Tracer
    {
        const string switchName = "PSMA";
        const string sourceName = "PSMA";
        public static TraceSource trace = new TraceSource(sourceName, SourceLevels.All);

        public static void Enter(string entryPoint)
        {
            TraceInformation("enter {0}", entryPoint);
        }
        public static void Exit(string entryPoint)
        {
            TraceInformation("exit {0}", entryPoint);
        }
        public static void TraceInformation(string message, params object[] param)
        {
            trace.TraceInformation(message, param);
        }
        public static void TraceWarning(string message, int warningCode = 1, params object[] param)
        {
            string msg = string.Format(message, param);
            trace.TraceEvent(TraceEventType.Warning, warningCode, GetMessageFromException(null, msg));
        }
        internal static string GetMessageFromException(Exception ex, string message)
        {
            if (ex == null)
                return message;
            else
                return string.Format("{0}, {1}", message, ex.GetBaseException()?.Message);
        }
        public static void TraceError(string message, int id, params object[] param)
        {
            trace.TraceEvent(TraceEventType.Error, id, message, param);
        }
        public static void TraceError(string message, Exception ex, int errorCode = 1)
        {
            string msg = GetMessageFromException(ex, message);
            trace.TraceEvent(TraceEventType.Error, ex.HResult, msg);
        }
        public static void TraceError(string message, params object[] param)
        {
            TraceError(message, 0, param);
        }
        static Tracer()
        {
            SourceSwitch sw = new SourceSwitch(switchName, switchName);
            sw.Level = SourceLevels.All;
            trace.Switch = sw;
        }
    }
}
