using System;
using System.Diagnostics;
using System.Text;

namespace Granfeldt
{
	public static class Tracer
	{
		//TODO: convert ident to stringbuilder
		const string SwitchName = "PSMA";
		const string SourceName = "PSMA";
		public static TraceSource Trace = new TraceSource(SourceName, SourceLevels.All);
		static string IndentText = ""; 

		public static int IndentLevel
		{
			get
			{
				return IndentText.Length;
			}
			set
			{
				IndentText = "";
			}
		}
		public static void Indent()
		{
			IndentText = IndentText + "  ";
		}
		public static void Unindent()
		{
			IndentText = IndentText.EndsWith("  ") ? IndentText.Remove(IndentText.Length - 2) : IndentText;
		}
		public static void Enter(string entryPoint)
		{
			TraceInformation("enter {0}", entryPoint);
			Indent();
			Process currentProc = Process.GetCurrentProcess();
			Tracer.TraceInformation("memory-usage {0:n0}Kb, private memory {1:n0}Kb", GC.GetTotalMemory(true) / 1024, currentProc.PrivateMemorySize64 / 1024);
		}
		public static void Exit(string entryPoint)
		{
			Process currentProc = Process.GetCurrentProcess();
			Tracer.TraceInformation("memory-usage {0:n0}Kb, private memory {1:n0}Kb", GC.GetTotalMemory(true) / 1024, currentProc.PrivateMemorySize64 / 1024);
			Unindent();
			TraceInformation("exit {0}", entryPoint);
		}
		public static void TraceInformation(string message, params object[] param)
		{
			Trace.TraceInformation(IndentText + message, param);
		}
		public static void TraceWarning(string message, params object[] param)
		{
			Trace.TraceEvent(TraceEventType.Warning, -1, IndentText + message, param);
		}
		public static void TraceError(string message, int id, params object[] param)
		{
			Trace.TraceEvent(TraceEventType.Error, id, IndentText + message, param);
		}
		public static void TraceError(string message, Exception ex)
		{
			Trace.TraceEvent(TraceEventType.Error, ex.HResult, IndentText + "{0}, {1}", message, ex.Message);
		}
		public static void TraceError(string message, params object[] param)
		{
			TraceError(message, -2, param);
		}
		static Tracer()
		{
			SourceSwitch sw = new SourceSwitch(SwitchName, SwitchName);
			sw.Level = SourceLevels.All;
			Trace.Switch = sw;
		}
	}
}
