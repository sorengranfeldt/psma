using Microsoft.MetadirectoryServices;
using System;
using System.Collections.Generic;
using System.IO;

namespace Granfeldt
{
	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
		IList<ConfigParameterDefinition> IMAExtensible2GetParameters.GetConfigParameters(System.Collections.ObjectModel.KeyedCollection<string, ConfigParameter> configParameters, ConfigParameterPage page)
		{
			Tracer.Enter("getconfigparameters");
			try
			{
				List<ConfigParameterDefinition> configParametersDefinitions = new List<ConfigParameterDefinition>();
				switch (page)
				{
					case ConfigParameterPage.Connectivity:
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("The Schema script is called to retrieve the object and attribute definitions. This script should be accessible to the FIM Synchronization Service service account during configuration and refreshes of the schema."));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.SchemaScript, ""));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateDividerParameter());
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("Authentication (optional): These credentials are passed as parameters to all scripts."));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.Username, ""));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateEncryptedStringParameter(Constants.Parameters.Password, ""));

						configParametersDefinitions.Add(ConfigParameterDefinition.CreateDividerParameter());
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("Impersonation (optional): If username and password below are specified (domain optional), the specified user is used to run all scripts. If not specified,  the scripts are run in the security context of the FIM Synchronization Service service account."));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.ImpersonationDomain, ""));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.ImpersonationUsername, ""));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateEncryptedStringParameter(Constants.Parameters.ImpersonationPassword, ""));

						break;
					case ConfigParameterPage.Global:
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("Scripts"));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("These are the PowerShell scripts that are run on the different operations. You should specify the full path of the scripts. Path cannot include spaces or similar whitespaces."));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.ImportScript, ""));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.ExportScript, ""));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateCheckBoxParameter(Constants.Parameters.UsePagedImport, false));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateDividerParameter());
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("If you enable Password Management, this script is called for both password change and set (requires PCNS)."));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.PasswordManagementScript, ""));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateDividerParameter());
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("The objects piped to the export script will normally be of type PSCustomObject. If you uncheck this, you will get objects of more complex type CSEntryChange instead (legacy behaviour). For more information on the CSEntryChange object type, please see MSDN Library."));
						configParametersDefinitions.Add(ConfigParameterDefinition.CreateCheckBoxParameter(Constants.Parameters.ExportSimpleObjects, true));
						break;
					case ConfigParameterPage.Partition:
						break;
					case ConfigParameterPage.RunStep:
						break;
				}

				return configParametersDefinitions;
			}
			catch (Exception ex)
			{
				Tracer.TraceError("getconfigparameters", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("getconfigparameters");
			}
		}
		ParameterValidationResult IMAExtensible2GetParameters.ValidateConfigParameters(System.Collections.ObjectModel.KeyedCollection<string, ConfigParameter> configParameters, ConfigParameterPage page)
		{
			try
			{
				Tracer.Enter("validateconfigparameters");
				if (page == ConfigParameterPage.Connectivity)
				{
					string schemaScriptFilename = Path.GetFullPath(configParameters[Constants.Parameters.SchemaScript].Value);
					if (!File.Exists(schemaScriptFilename))
					{
						return new ParameterValidationResult(ParameterValidationResultCode.Failure, string.Format("Can not find or access Schema script '{0}'. Please make sure that the FIM Synchronization Service service account can read and access this file.", schemaScriptFilename), Constants.Parameters.SchemaScript);
					}
				}
				if (page == ConfigParameterPage.Global)
				{
					string importScriptFilename = Path.GetFullPath(configParameters[Constants.Parameters.ImportScript].Value);
					if (!File.Exists(importScriptFilename))
					{
						return new ParameterValidationResult(ParameterValidationResultCode.Failure, string.Format("Can not find or access Import script '{0}'. Please make sure that the FIM Synchronization Service service account can read and access this file.", importScriptFilename), Constants.Parameters.ImportScript);
					}
					string exportScriptFilename = Path.GetFullPath(configParameters[Constants.Parameters.ExportScript].Value);
					if (!File.Exists(exportScriptFilename))
					{
						return new ParameterValidationResult(ParameterValidationResultCode.Failure, string.Format("Can not find or access Export script '{0}'. Please make sure that the FIM Synchronization Service service account can read and access this file.", exportScriptFilename), Constants.Parameters.ExportScript);
					}
					string passwordManagementScriptFilename = Path.GetFullPath(configParameters[Constants.Parameters.PasswordManagementScript].Value);
					if (!File.Exists(passwordManagementScriptFilename))
					{
						return new ParameterValidationResult(ParameterValidationResultCode.Failure, string.Format("Can not find or access Password Management script '{0}'. Please make sure that the FIM Synchronization Service service account can read and access this file.", passwordManagementScriptFilename), Constants.Parameters.PasswordManagementScript);
					}
				}
			}
			catch (Exception ex)
			{
				Tracer.TraceError("validateconfigparameters", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("validateconfigparameters");
			}
			return new ParameterValidationResult(ParameterValidationResultCode.Success, "", "");
		}
		public void InitializeConfigParameters(System.Collections.ObjectModel.KeyedCollection<string, ConfigParameter> configParameters)
		{
			Tracer.Enter("initializeconfigparameters");
			try
			{
				if (configParameters != null)
				{
					foreach (ConfigParameter cp in configParameters)
					{
						Tracer.TraceInformation("{0}: '{1}'", cp.Name, cp.IsEncrypted ? "*** secret ***" : cp.Value);
						if (cp.Name.Equals(Constants.Parameters.Username)) Username = configParameters[cp.Name].Value;
						if (cp.Name.Equals(Constants.Parameters.Password))
						{
							Password = configParameters[cp.Name].SecureValue.ConvertToUnsecureString();
							SecureStringPassword = configParameters[cp.Name].SecureValue;
                        }

						if (cp.Name.Equals(Constants.Parameters.ImpersonationDomain)) impersonationUserDomain = configParameters[cp.Name].Value;
						if (cp.Name.Equals(Constants.Parameters.ImpersonationUsername)) impersonationUsername = configParameters[cp.Name].Value;
						if (cp.Name.Equals(Constants.Parameters.ImpersonationPassword)) impersonationUserPassword = configParameters[cp.Name].SecureValue.ConvertToUnsecureString();

						if (cp.Name.Equals(Constants.Parameters.SchemaScript)) SchemaScript = configParameters[cp.Name].Value;
						if (cp.Name.Equals(Constants.Parameters.ImportScript)) ImportScript = configParameters[cp.Name].Value;
						if (cp.Name.Equals(Constants.Parameters.ExportScript)) ExportScript = configParameters[cp.Name].Value;
						if (cp.Name.Equals(Constants.Parameters.PasswordManagementScript)) PasswordManagementScript = configParameters[cp.Name].Value;
						if (cp.Name.Equals(Constants.Parameters.ExportSimpleObjects)) ExportSimpleObjects = configParameters[cp.Name].Value == "0" ? false : true;
						if (cp.Name.Equals(Constants.Parameters.UsePagedImport)) UsePagedImport = configParameters[cp.Name].Value == "0" ? false : true;
					}
				}
			}
			catch (Exception ex)
			{
				Tracer.TraceError("initializeconfigparameters", ex);
				throw;
			}
			finally
			{
				Tracer.Exit("initializeconfigparameters");
			}
		}

	}

}
