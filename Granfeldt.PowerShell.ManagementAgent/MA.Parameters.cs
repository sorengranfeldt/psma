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
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.UsernameAux, ""));
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateEncryptedStringParameter(Constants.Parameters.PasswordAux, ""));

                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateDividerParameter());
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("Impersonation (optional): If username and password below are specified (domain optional), the specified user is used to run all scripts. If not specified,  the scripts are run in the security context of the FIM Synchronization Service service account."));
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.ImpersonationDomain, ""));
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.ImpersonationUsername, ""));
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateEncryptedStringParameter(Constants.Parameters.ImpersonationPassword, ""));

                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateDividerParameter());
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("PowerShell Engine Configuration: Select which PowerShell engine to use for script execution."));
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateDropDownParameter(Constants.Parameters.PowerShellVersion, "Windows PowerShell 5.1,PowerShell 7", false, "Windows PowerShell 5.1"));
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(Constants.Parameters.PowerShell7ExecutablePath, ""));

                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateDividerParameter());
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateLabelParameter("Specify any additional configuration parameters to be passed to the Powershell scripts. Each value should be on a seperate line and key and value seperated by a comma or equal sign (i.e. Environment=PROD)"));
                        configParametersDefinitions.Add(ConfigParameterDefinition.CreateTextParameter(Constants.Parameters.ConfigurationParameters, ""));

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
                    
                    // Validate PowerShell 7 path if selected
                    if (configParameters.Contains(Constants.Parameters.PowerShellVersion) &&
                        configParameters[Constants.Parameters.PowerShellVersion]?.Value == "PowerShell 7")
                    {
                        if (!configParameters.Contains(Constants.Parameters.PowerShell7ExecutablePath) ||
                            string.IsNullOrWhiteSpace(configParameters[Constants.Parameters.PowerShell7ExecutablePath]?.Value))
                        {
                            return new ParameterValidationResult(ParameterValidationResultCode.Failure, 
                                "PowerShell 7 Executable Path is required when PowerShell 7 is selected.", 
                                Constants.Parameters.PowerShell7ExecutablePath);
                        }
                        
                        string powershell7ExecutableFilename = Path.GetFullPath(configParameters[Constants.Parameters.PowerShell7ExecutablePath].Value);
                        if (!File.Exists(powershell7ExecutableFilename))
                        {
                            return new ParameterValidationResult(ParameterValidationResultCode.Failure, string.Format("Can not find or access PowerShell 7 executable '{0}'. Please make sure that the FIM Synchronization Service service account can read and access this file.", powershell7ExecutableFilename), Constants.Parameters.PowerShell7ExecutablePath);
                        }
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
                Tracer.TraceInformation("*** ENHANCED PARAMETER DEBUGGING ***");
                Tracer.TraceInformation("config-parameters-collection-null: {0}", configParameters == null);
                if (configParameters != null)
                {
                    Tracer.TraceInformation("config-parameters-count: {0}", configParameters.Count);
                    
                    foreach (ConfigParameter cp in configParameters)
                    {
                        Tracer.TraceInformation("{0}: '{1}'", cp.Name, cp.IsEncrypted ? "*** secret ***" : cp.Value);
                        
                        // Enhanced PowerShell Version debugging
                        if (cp.Name.Equals(Constants.Parameters.PowerShellVersion))
                        {
                            Tracer.TraceInformation("*** FOUND POWERSHELL VERSION PARAMETER ***");
                            Tracer.TraceInformation("powershell-version-parameter-name: '{0}'", cp.Name);
                            Tracer.TraceInformation("powershell-version-parameter-value: '{0}'", cp.Value ?? "(null)");
                            Tracer.TraceInformation("powershell-version-constants-value: '{0}'", Constants.Parameters.PowerShellVersion);
                            PowerShellVersion = configParameters[cp.Name].Value;
                            Tracer.TraceInformation("powershell-version-assigned: '{0}'", PowerShellVersion ?? "(null)");
                        }
                        
                        if (cp.Name.Equals(Constants.Parameters.Username)) Username = configParameters[cp.Name].Value;
                        if (cp.Name.Equals(Constants.Parameters.Password))
                        {
                            Password = configParameters[cp.Name].SecureValue.ConvertToUnsecureString();
                            SecureStringPassword = configParameters[cp.Name].SecureValue;
                        }

                        if (cp.Name.Equals(Constants.Parameters.UsernameAux)) UsernameAux = configParameters[cp.Name].Value;
                        if (cp.Name.Equals(Constants.Parameters.PasswordAux))
                        {
                            PasswordAux = configParameters[cp.Name].SecureValue.ConvertToUnsecureString();
                            SecureStringPasswordAux = configParameters[cp.Name].SecureValue;
                        }
                        if (cp.Name.Equals(Constants.Parameters.ConfigurationParameters))
                        {
                            // Split on newlines without using regex to avoid issues with file paths containing backslashes
                            string configValue = configParameters[cp.Name].Value ?? string.Empty;
                            string[] result = configValue.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                            if (result != null)
                            {
                                foreach (string s in result)
                                {
                                    string key = null;
                                    string value = null;
                                    if (getConfigurationParameter(s, out key, out value))
                                    {
                                        Tracer.TraceInformation("configuration-parameter key: '{0}', value: '{1}'", key, value);
                                        if (ConfigurationParameter.ContainsKey(key))
                                        {
                                            Tracer.TraceWarning("duplicate-configuration key: {0}", 1, key);
                                        }
                                        else
                                        {
                                            ConfigurationParameter.Add(key, value);
                                        }
                                    }
                                }
                            }
                        }

                        if (cp.Name.Equals(Constants.Parameters.ImpersonationDomain)) impersonationUserDomain = configParameters[cp.Name].Value;
                        if (cp.Name.Equals(Constants.Parameters.ImpersonationUsername)) impersonationUsername = configParameters[cp.Name].Value;
                        if (cp.Name.Equals(Constants.Parameters.ImpersonationPassword)) impersonationUserPassword = configParameters[cp.Name].SecureValue.ConvertToUnsecureString();

                        if (cp.Name.Equals(Constants.Parameters.SchemaScript))
                        {
                            schemaScriptPath = configParameters[cp.Name].Value;
                            Tracer.TraceInformation("schema-script-configured: '{0}'", schemaScriptPath ?? "(null)");
                        }
                        if (cp.Name.Equals(Constants.Parameters.ImportScript))
                        {
                            importScriptPath = configParameters[cp.Name].Value;
                            Tracer.TraceInformation("import-script-configured: '{0}'", importScriptPath ?? "(null)");
                        }
                        if (cp.Name.Equals(Constants.Parameters.ExportScript))
                        {
                            exportScriptPath = configParameters[cp.Name].Value;
                            Tracer.TraceInformation("export-script-configured: '{0}'", exportScriptPath ?? "(null)");
                        }
                        if (cp.Name.Equals(Constants.Parameters.PasswordManagementScript))
                        {
                            passwordManagementScriptPath = configParameters[cp.Name].Value;
                            Tracer.TraceInformation("password-script-configured: '{0}'", passwordManagementScriptPath ?? "(null)");
                        }
                        if (cp.Name.Equals(Constants.Parameters.ExportSimpleObjects)) exportSimpleObjects = configParameters[cp.Name].Value == "0" ? false : true;
                        if (cp.Name.Equals(Constants.Parameters.UsePagedImport)) usePagedImport = configParameters[cp.Name].Value == "0" ? false : true;
                        // PowerShellVersion and PowerShell7ExecutablePath already processed in the enhanced debugging section above
                    }
                }

                // Set default values if not provided
                if (string.IsNullOrEmpty(PowerShellVersion))
                {
                    PowerShellVersion = "Windows PowerShell 5.1";
                }
                if (string.IsNullOrEmpty(PowerShell7ExecutablePath))
                {
                    // Use forward slashes initially to avoid regex issues, will be normalized by Path.GetFullPath later
                    PowerShell7ExecutablePath = "C:/Program Files/PowerShell/7/pwsh.exe";
                }

                Tracer.TraceInformation("powershell-version: '{0}'", PowerShellVersion);
                Tracer.TraceInformation("powershell7-executable-path: '{0}'", PowerShell7ExecutablePath);
                
                // ENHANCED DEBUG: Detailed configuration validation
                Tracer.TraceInformation("*** ENHANCED CONFIGURATION DEBUG ***");
                Tracer.TraceInformation("powershell-version-is-null: {0}", PowerShellVersion == null);
                Tracer.TraceInformation("powershell-version-contains-ps7: {0}", PowerShellVersion != null && PowerShellVersion.Contains("PowerShell 7"));
                Tracer.TraceInformation("powershell7-path-exists: {0}", !string.IsNullOrEmpty(PowerShell7ExecutablePath) && System.IO.File.Exists(PowerShell7ExecutablePath));
                if (!string.IsNullOrEmpty(PowerShell7ExecutablePath) && !System.IO.File.Exists(PowerShell7ExecutablePath))
                {
                    Tracer.TraceError("powershell7-executable-not-found-at-configured-path: '{0}'", PowerShell7ExecutablePath);
                }
                
                // Log final configuration state
                Tracer.TraceInformation("*** FINAL SCRIPT CONFIGURATION STATE ***");
                Tracer.TraceInformation("schema-script-path: '{0}'", schemaScriptPath ?? "(null)");
                Tracer.TraceInformation("import-script-path: '{0}'", importScriptPath ?? "(null)");
                Tracer.TraceInformation("export-script-path: '{0}'", exportScriptPath ?? "(null)");
                Tracer.TraceInformation("password-script-path: '{0}'", passwordManagementScriptPath ?? "(null)");
                Tracer.TraceInformation("use-paged-import: {0}", usePagedImport);
                Tracer.TraceInformation("export-simple-objects: {0}", exportSimpleObjects);
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

        bool getConfigurationParameter(string input, out string key, out string value)
        {
            key = null;
            value = null;
            
            if (string.IsNullOrWhiteSpace(input))
            {
                return false;
            }

            // Find the first occurrence of = or , 
            int separatorIndex = -1;
            
            int equalsIndex = input.IndexOf('=');
            int commaIndex = input.IndexOf(',');
            
            if (equalsIndex >= 0 && (commaIndex < 0 || equalsIndex < commaIndex))
            {
                separatorIndex = equalsIndex;
            }
            else if (commaIndex >= 0)
            {
                separatorIndex = commaIndex;
            }
            
            if (separatorIndex > 0)
            {
                key = input.Substring(0, separatorIndex).Trim();
                if (separatorIndex + 1 < input.Length)
                {
                    value = input.Substring(separatorIndex + 1);
                }
                else
                {
                    value = string.Empty;
                }
                return !string.IsNullOrWhiteSpace(key);
            }
            
            // If no separator found, treat the entire input as the key
            key = input.Trim();
            value = string.Empty;
            return !string.IsNullOrWhiteSpace(key);
        }
    }

}
