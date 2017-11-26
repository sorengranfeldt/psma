using Microsoft.MetadirectoryServices;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text.RegularExpressions;

namespace Granfeldt
{

	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
		int exportBatchSize;
		bool ExportSimpleObjects = true;
		string ExportScript = null;
		OperationType exportType;
		Collection<PSObject> exportResults;

		int IMAExtensible2CallExport.ExportDefaultPageSize
		{
			get { return 100; }
		}
		int IMAExtensible2CallExport.ExportMaxPageSize
		{
			get { return 500; }
		}
		void IMAExtensible2CallExport.OpenExportConnection(System.Collections.ObjectModel.KeyedCollection<string, ConfigParameter> configParameters, Schema types, OpenExportConnectionRunStep exportRunStep)
		{
			Tracer.IndentLevel = 0;
			Tracer.Enter("openexportconnection");
			Tracer.Indent();
			try
			{
				InitializeConfigParameters(configParameters);

				OpenRunspace();
				schema = types;

				exportType = exportRunStep.ExportType;
				Tracer.TraceInformation("export-type '{0}'", exportType);
				exportBatchSize = exportRunStep.BatchSize;
				Tracer.TraceInformation("export-batch-size '{0}'", exportBatchSize);
			}
			catch (Exception ex)
			{
				Tracer.TraceError("openexportconnection", ex);
				throw new TerminateRunException(ex.Message);
			}
			finally
			{
				Tracer.Unindent();
				Tracer.Exit("openexportconnection");
			}
		}
		PutExportEntriesResults IMAExtensible2CallExport.PutExportEntries(IList<CSEntryChange> csentries)
		{
			Tracer.Enter("putexportentries");
			Tracer.Indent();
			PutExportEntriesResults exportEntries = new PutExportEntriesResults();
			PSDataCollection<PSObject> exportPipeline = new PSDataCollection<PSObject>();
			try
			{
				Command cmd = new Command(Path.GetFullPath(ExportScript));
				cmd.Parameters.Add(new CommandParameter("User", Username));
				cmd.Parameters.Add(new CommandParameter("Password", Password));
				cmd.Parameters.Add(new CommandParameter("Credentials", GetSecureCredentials()));
				cmd.Parameters.Add(new CommandParameter("ExportType", exportType));

				foreach (CSEntryChange csentryChange in csentries)
				{
					Tracer.TraceInformation("adding-object id: {0}, dn: '{1}' [{2}]", csentryChange.Identifier, csentryChange.DN, csentryChange.ObjectModificationType);
					if (ExportSimpleObjects)
					{
						// http://karlprosser.com/coder/2008/06/12/generating-a-propertybag-aka-pscustomobject-in-c/
						// creating a PSobject without any parameters in the constructor creates a PSCustomObject
						PSObject obj = new PSObject();
						// PSNoteProperties are not strongly typed but do contain an explicit type.
						obj.Properties.Add(new PSNoteProperty(Constants.ControlValues.Identifier, csentryChange.Identifier.ToString()));
						obj.Properties.Add(new PSNoteProperty(Constants.ControlValues.Anchor, csentryChange.AnchorAttributes.Count > 0 ? csentryChange.AnchorAttributes.FirstOrDefault().Value : ""));
						obj.Properties.Add(new PSAliasProperty(Constants.ControlValues.IdentifierAsGuid, csentryChange.Identifier.ToString(), typeof(Guid)));
						obj.Properties.Add(new PSNoteProperty(Constants.ControlValues.ObjectModificationType, csentryChange.ObjectModificationType.ToString()));
						obj.Properties.Add(new PSNoteProperty(Constants.ControlValues.ObjectType, csentryChange.ObjectType));

						List<string> attrs = schema.Types[csentryChange.ObjectType].Attributes.Select(a => a.Name).ToList<string>();
						obj.Properties.Add(new PSNoteProperty(Constants.ControlValues.AttributeNames, attrs));

						obj.Properties.Add(new PSNoteProperty(Constants.ControlValues.ChangedAttributeNames, csentryChange.ChangedAttributeNames == null ? new List<string>() : csentryChange.ChangedAttributeNames));
						obj.Properties.Add(new PSNoteProperty(Constants.ControlValues.DN, csentryChange.DN));
						obj.Properties.Add(new PSNoteProperty(Constants.ControlValues.RDN, csentryChange.RDN));
						foreach (AttributeChange ac in csentryChange.AttributeChanges)
						{
							if (!ac.IsMultiValued)
							{
								foreach (ValueChange vc in ac.ValueChanges)
								{
									obj.Properties.Add(new PSNoteProperty(string.Format("{0}", ac.Name), vc.Value));
								}
							}
							else
							{
								List<object> values = new List<object>();
								foreach (ValueChange vc in ac.ValueChanges)
								{
									values.Add(vc.Value);
								}
								obj.Properties.Add(new PSNoteProperty(string.Format("{0}", ac.Name), values.ToArray()));
							}
						}
						exportPipeline.Add(obj);
					}
					else
					{
						exportPipeline.Add(new PSObject(csentryChange));
					}
				}

				exportResults = InvokePowerShellScript(cmd, exportPipeline);

				if (exportResults != null)
				{
					foreach (PSObject result in exportResults)
					{
						if (result.BaseObject.GetType() != typeof(System.Collections.Hashtable))
						{
							continue;
						}
						Hashtable hashTable = (Hashtable)result.BaseObject;
						string ErrorName = "unspecified-error";
						string ErrorDetail = "No details specified";
						Guid identifier = new Guid();

						// get anchor attribute changes
						List<AttributeChange> attrchanges = new List<AttributeChange>();
						foreach (string key in hashTable.Keys)
						{
							if (key.Equals(Constants.ControlValues.Identifier, StringComparison.OrdinalIgnoreCase))
							{
								try
								{
									identifier = new Guid(hashTable[key].ToString());
									Tracer.TraceInformation("got-identifier {0}, {1}", identifier, key);
								}
								catch (FormatException fex)
								{
									Tracer.TraceError("identifier-format-error '{0}'", fex.ToString());
								}
								continue;
							}
							if (key.Equals(Constants.ControlValues.ErrorName, StringComparison.OrdinalIgnoreCase))
							{
								ErrorName = hashTable[key].ToString();
								Tracer.TraceInformation("got-errorname {0}, {1}", ErrorName, key);
								continue;
							}
							if (key.Equals(Constants.ControlValues.ErrorDetail, StringComparison.OrdinalIgnoreCase))
							{
								ErrorDetail = hashTable[key].ToString();
								Tracer.TraceInformation("got-errordetail {0}, {1}", ErrorDetail, key);
								continue;
							}
							if (!(Regex.IsMatch(key, @"^\[.+\]$", RegexOptions.IgnoreCase)))
							{
								Tracer.TraceInformation("got-attribute-change {0}: '{1}'", key, hashTable[key]);
								attrchanges.Add(AttributeChange.CreateAttributeAdd(key, hashTable[key]));
								continue;
							}
						}

						if (string.IsNullOrEmpty(ErrorName) || ErrorName.Equals("success", StringComparison.OrdinalIgnoreCase))
						{
							Tracer.TraceInformation("returning-success id: {0}", identifier);
							CSEntryChangeResult cschangeresult = CSEntryChangeResult.Create(identifier, attrchanges, MAExportError.Success);
							exportEntries.CSEntryChangeResults.Add(cschangeresult);
						}
						else
						{
							Tracer.TraceInformation("returning-error id: {0}, name: {1}, details: {2}", identifier, ErrorName, ErrorDetail);
							CSEntryChangeResult cschangeresult = CSEntryChangeResult.Create(identifier, attrchanges, MAExportError.ExportErrorCustomContinueRun, ErrorName, ErrorDetail);
							exportEntries.CSEntryChangeResults.Add(cschangeresult);
						}
					}
				}
				exportPipeline.Clear();
				exportResults.Clear();
				exportResults = null;
				return exportEntries;
			}
			catch (Exception ex)
			{
				Tracer.TraceError("putexportentries", ex);
				throw;
			}
			finally
			{
				Tracer.Unindent();
				Tracer.Exit("putexportentries");
			}
		}
		void IMAExtensible2CallExport.CloseExportConnection(CloseExportConnectionRunStep exportRunStep)
		{
			Tracer.Enter("closeexportconnection");
			Tracer.Indent();
			try
			{
				CloseRunspace();
				Dispose();
			}
			catch (Exception ex)
			{
				Tracer.TraceError("closeexportconnection", ex);
				throw;
			}
			finally
			{
				Tracer.Unindent();
				Tracer.Exit("closeexportconnection");
			}
		}
	}
}
