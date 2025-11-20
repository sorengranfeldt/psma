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

        public static void Enter(string entryPoint) => TraceInformation($"enter {entryPoint}");
        public static void Exit(string entryPoint) => TraceInformation($"exit {entryPoint}");

        public static void TraceInformation(string message, params object[] param)
        {
            if (param == null || param.Length == 0)
            {
                // No parameters provided, treat message as literal text to avoid format string issues
                trace.TraceInformation($"{message}");
            }
            else
            {
                try
                {
                    // Parameters provided, format the message safely
                    trace.TraceInformation(message, param);
                }
                catch (FormatException)
                {
                    // If format fails, use safe concatenation
                    var sb = new StringBuilder(message ?? "");
                    sb.Append(" [params: ");
                    for (int i = 0; i < param.Length; i++)
                    {
                        if (i > 0) sb.Append(", ");
                        sb.Append(param[i]?.ToString() ?? "null");
                    }
                    sb.Append("]");
                    trace.TraceInformation("{0}", sb.ToString());
                }
            }
        }
        public static void TraceWarning(string message, int warningCode = 1, params object[] param)
        {
            // Use safe approach to avoid format string exceptions
            string msg;
            if (param == null || param.Length == 0)
            {
                // No parameters provided, treat message as literal text
                msg = message ?? "";
            }
            else
            {
                try
                {
                    msg = string.Format(message, param);
                }
                catch (FormatException)
                {
                    // If format fails, concatenate the message with parameters safely
                    var sb = new StringBuilder(message ?? "");
                    sb.Append(" [params: ");
                    for (int i = 0; i < param.Length; i++)
                    {
                        if (i > 0) sb.Append(", ");
                        sb.Append(param[i]?.ToString() ?? "null");
                    }
                    sb.Append("]");
                    msg = sb.ToString();
                }
            }
            trace.TraceEvent(TraceEventType.Warning, warningCode, "{0}", GetMessageFromException(null, msg));
        }
        internal static string GetMessageFromException(Exception ex, string message)
        {
            if (ex == null)
                return message ?? "";
            else
            {
                // Use string interpolation to completely avoid format string issues
                string safemessage = message ?? "";
                string safeException = ex.GetBaseException()?.Message ?? "Unknown error";
                return $"{safemessage}, {safeException}";
            }
        }
        public static void TraceError(string message, int id, params object[] param)
        {
            if (param == null || param.Length == 0)
            {
                // No parameters provided, treat message as literal text to avoid format string issues
                trace.TraceEvent(TraceEventType.Error, id, "{0}", message);
            }
            else
            {
                try
                {
                    // Parameters provided, format the message safely
                    trace.TraceEvent(TraceEventType.Error, id, message, param);
                }
                catch (FormatException)
                {
                    // If format fails, use safe concatenation
                    var sb = new StringBuilder(message ?? "");
                    sb.Append(" [params: ");
                    for (int i = 0; i < param.Length; i++)
                    {
                        if (i > 0) sb.Append(", ");
                        sb.Append(param[i]?.ToString() ?? "null");
                    }
                    sb.Append("]");
                    trace.TraceEvent(TraceEventType.Error, id, "{0}", sb.ToString());
                }
            }
        }
        public static void TraceError(string message, Exception ex, int errorCode = 1)
        {
            string msg = GetMessageFromException(ex, message);
            trace.TraceEvent(TraceEventType.Error, errorCode, "{0}", msg);
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
