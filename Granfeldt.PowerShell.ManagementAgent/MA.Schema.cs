using Microsoft.MetadirectoryServices;
using System;
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
        Collection<PSObject> schemaResults;

        class AttributeDefinition
        {
            public string Name { get; set; }
            public AttributeType Type { get; set; }
            public bool IsMultiValue { get; set; }
            public bool IsAnchor { get; set; }
            public bool ImportOnly { get; set; }
            public bool ExportOnly { get; set; }
        }

        // define a dictionary to map attribute types to AttributeType enum values
        Dictionary<string, AttributeType> typeMappings = new Dictionary<string, AttributeType>
        {
            { "boolean", AttributeType.Boolean },
            { "binary", AttributeType.Binary },
            { "integer", AttributeType.Integer },
            { "reference", AttributeType.Reference },
            { "string", AttributeType.String }
        };

        Schema IMAExtensible2GetSchema.GetSchema(KeyedCollection<string, ConfigParameter> configParameters)
        {
            Tracer.Enter("getschema");
            try
            {

                Schema schema = Schema.Create();
                InitializeConfigParameters(configParameters);

                IPSEngine engine = new PSEnginePwsh7();
                //engine.InvokeCommand("Set-ExecutionPolicy", new System.Collections.Hashtable { ["Scope"] = "Process", ["ExecutionPolicy"] = "Bypass", ["Force"] = true });

                // Validate schema script path is configured
                if (string.IsNullOrEmpty(schemaScriptPath))
                {
                    Tracer.TraceError("schema-script-path-not-configured");
                    throw new InvalidOperationException("Schema script path is not configured. Please configure the 'Schema Script' parameter in the management agent configuration.");
                }

                // Validate schema script file exists
                if (!File.Exists(schemaScriptPath))
                {
                    Tracer.TraceError("schema-script-file-not-found: {0}", schemaScriptPath);
                    throw new FileNotFoundException($"Schema script file not found: {schemaScriptPath}");
                }

                Tracer.TraceInformation("using-schema-script: {0}", schemaScriptPath);
                
                engine.OpenRunspace();

                Command cmd = new Command(Path.GetFullPath(schemaScriptPath));
                cmd.Parameters.Add(new CommandParameter("Username", Username));
                cmd.Parameters.Add(new CommandParameter("Password", Password));
                cmd.Parameters.Add(new CommandParameter("Credentials", GetSecureCredentials(Username, SecureStringPassword)));

                cmd.Parameters.Add(new CommandParameter("AuxUsername", UsernameAux));
                cmd.Parameters.Add(new CommandParameter("AuxPassword", PasswordAux));
                cmd.Parameters.Add(new CommandParameter("AuxCredentials", GetSecureCredentials(UsernameAux, SecureStringPasswordAux)));

                cmd.Parameters.Add(new CommandParameter("ConfigurationParameter", ConfigurationParameter));

                cmd.Parameters.ToDictionary(p => p.Name, p => p.Value);
                // Schema operations should always use Windows PowerShell 5.1 for backwards compatibility

                schemaResults = engine.InvokeCommand(Path.GetFullPath(schemaScriptPath), cmd.Parameters.ToDictionary(p => p.Name, p => p.Value), null);

                //schemaResults = InvokePowerShellScript(cmd, null, allowPowerShell7: false);
                engine.CloseRunspace();

                if (schemaResults == null)
                {
                    Tracer.TraceError("schema-script-returned-null-results");
                    throw new InvalidOperationException("Schema script returned no results. Please check that the schema script is working correctly and returns valid schema objects.");
                }

                if (schemaResults.Count == 0)
                {
                    Tracer.TraceError("schema-script-returned-empty-results");
                    throw new InvalidOperationException("Schema script returned empty results. Please check that the schema script is working correctly and returns valid schema objects.");
                }

                Tracer.TraceInformation("schema-script-returned-object-count: {0}", schemaResults.Count);
                if (schemaResults != null)
                {
                    foreach (PSObject obj in schemaResults)
                    {
                        string objectTypeName = null;
                        HashSet<AttributeDefinition> attrs = new HashSet<AttributeDefinition>();

                        foreach (PSPropertyInfo p in obj.Properties)
                        {
                            string[] elements = p.Name.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
                            string attrName = elements[0].Trim();
                            string attrType = elements[1].Trim();

                            if (string.Equals(attrName, Constants.ControlValues.ObjectClass, StringComparison.OrdinalIgnoreCase))
                            {
                                objectTypeName = p.Value.ToString();
                                Tracer.TraceInformation("object-class '{0}'", objectTypeName);
                            }
                            else
                            {
                                AttributeDefinition ad = new AttributeDefinition();
                                ad.Name = Regex.Replace(attrName, "^(Anchor-|ImportOnly-|ExportOnly-)", "", RegexOptions.IgnoreCase);

                                ad.IsAnchor = p.Name.StartsWith("anchor-", StringComparison.OrdinalIgnoreCase);
                                ad.ImportOnly = p.Name.StartsWith("importonly-", StringComparison.OrdinalIgnoreCase);
                                ad.ExportOnly = p.Name.StartsWith("exportonly-", StringComparison.OrdinalIgnoreCase);
                                ad.IsMultiValue = p.Name.EndsWith("[]", StringComparison.OrdinalIgnoreCase);

                                // get the attribute type without array notation and convert to lowercase and
                                // set ad.Type based on the dictionary mapping or default to AttributeType.String
                                string cleanedAttrType = attrType.Replace("[]", "").ToLower();
                                ad.Type = typeMappings.ContainsKey(cleanedAttrType) ? typeMappings[cleanedAttrType] : AttributeType.String;

                                Tracer.TraceInformation("name '{0}', isanchor: {1}, ismultivalue: {2}, importonly: {3}, exportonly: {4}, type: {5}", ad.Name, ad.IsAnchor, ad.IsMultiValue, ad.ImportOnly, ad.ExportOnly, ad.Type);
                                attrs.Add(ad);
                            }
                        }
                        if (string.IsNullOrEmpty(objectTypeName))
                        {
                            Tracer.TraceError("missing-object-class");
                            // Simplified logging to avoid format string issues
                            try
                            {
                                Tracer.TraceError("schema-object-properties-found: " + obj.Properties.ToList().Count.ToString());
                                foreach (PSPropertyInfo prop in obj.Properties)
                                {
                                    string propName = prop.Name ?? "(null)";
                                    string propValue = prop.Value?.ToString() ?? "(null)";
                                    Tracer.TraceError("schema-property: '" + propName + "' = '" + propValue + "'");
                                }
                            }
                            catch (Exception traceEx)
                            {
                                Tracer.TraceError("error-during-schema-property-logging", traceEx);
                            }
                            throw new NoSuchObjectTypeException("Schema script returned an object without the required 'objectClass|string' property. Please ensure your schema script returns objects with proper objectClass definitions.");
                        }

                        SchemaType objectClass = SchemaType.Create(objectTypeName, true);
                        foreach (AttributeDefinition def in attrs)
                        {
                            if (def.IsAnchor)
                            {
                                objectClass.Attributes.Add(SchemaAttribute.CreateAnchorAttribute(def.Name, def.Type));
                            }
                            else
                            {
                                var attrOperation = def.ExportOnly ? AttributeOperation.ExportOnly :
                                                    def.ImportOnly ? AttributeOperation.ImportOnly : AttributeOperation.ImportExport;

                                if (def.IsMultiValue)
                                {
                                    objectClass.Attributes.Add(SchemaAttribute.CreateMultiValuedAttribute(def.Name, def.Type, attrOperation));
                                }
                                else
                                {
                                    objectClass.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute(def.Name, def.Type, attrOperation));
                                }
                            }
                        }
                        if (objectClass.AnchorAttributes.Count == 1)
                        {
                            schema.Types.Add(objectClass);
                        }
                        else
                        {
                            Tracer.TraceError("missing-anchor-definition-on-object");
                            throw new AttributeNotPresentException();
                        }
                    }
                }
                schemaResults.Clear();
                return schema;
            }
            catch (Exception ex)
            {
                Tracer.TraceError("getschema", ex);
                throw;
            }
            finally
            {
                Tracer.Exit("getschema");
            }
        }

        //Schema IMAExtensible2GetSchema.GetSchema(KeyedCollection<string, ConfigParameter> configParameters)
        //{
        //    Tracer.Enter("getschema");
        //    try
        //    {
        //        Schema schema = Schema.Create();
        //        InitializeConfigParameters(configParameters);

        //        // Validate schema script path is configured
        //        if (string.IsNullOrEmpty(schemaScriptPath))
        //        {
        //            Tracer.TraceError("schema-script-path-not-configured");
        //            throw new InvalidOperationException("Schema script path is not configured. Please configure the 'Schema Script' parameter in the management agent configuration.");
        //        }

        //        // Validate schema script file exists
        //        if (!File.Exists(schemaScriptPath))
        //        {
        //            Tracer.TraceError("schema-script-file-not-found: {0}", schemaScriptPath);
        //            throw new FileNotFoundException($"Schema script file not found: {schemaScriptPath}");
        //        }

        //        Tracer.TraceInformation("using-schema-script: {0}", schemaScriptPath);
        //        OpenRunspace();
        //        Command cmd = new Command(Path.GetFullPath(schemaScriptPath));
        //        cmd.Parameters.Add(new CommandParameter("Username", Username));
        //        cmd.Parameters.Add(new CommandParameter("Password", Password));
        //        cmd.Parameters.Add(new CommandParameter("Credentials", GetSecureCredentials(Username, SecureStringPassword)));

        //        cmd.Parameters.Add(new CommandParameter("AuxUsername", UsernameAux));
        //        cmd.Parameters.Add(new CommandParameter("AuxPassword", PasswordAux));
        //        cmd.Parameters.Add(new CommandParameter("AuxCredentials", GetSecureCredentials(UsernameAux, SecureStringPasswordAux)));

        //        cmd.Parameters.Add(new CommandParameter("ConfigurationParameter", ConfigurationParameter));

        //        // Schema operations should always use Windows PowerShell 5.1 for backwards compatibility
        //        schemaResults = InvokePowerShellScript(cmd, null, allowPowerShell7: false);
        //        CloseRunspace();

        //        if (schemaResults == null)
        //        {
        //            Tracer.TraceError("schema-script-returned-null-results");
        //            throw new InvalidOperationException("Schema script returned no results. Please check that the schema script is working correctly and returns valid schema objects.");
        //        }

        //        if (schemaResults.Count == 0)
        //        {
        //            Tracer.TraceError("schema-script-returned-empty-results");
        //            throw new InvalidOperationException("Schema script returned empty results. Please check that the schema script is working correctly and returns valid schema objects.");
        //        }

        //        Tracer.TraceInformation("schema-script-returned-object-count: {0}", schemaResults.Count);
        //        if (schemaResults != null)
        //        {
        //            foreach (PSObject obj in schemaResults)
        //            {
        //                string objectTypeName = null;
        //                HashSet<AttributeDefinition> attrs = new HashSet<AttributeDefinition>();

        //                foreach (PSPropertyInfo p in obj.Properties)
        //                {
        //                    string[] elements = p.Name.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
        //                    string attrName = elements[0].Trim();
        //                    string attrType = elements[1].Trim();

        //                    if (string.Equals(attrName, Constants.ControlValues.ObjectClass, StringComparison.OrdinalIgnoreCase))
        //                    {
        //                        objectTypeName = p.Value.ToString();
        //                        Tracer.TraceInformation("object-class '{0}'", objectTypeName);
        //                    }
        //                    else
        //                    {
        //                        AttributeDefinition ad = new AttributeDefinition();
        //                        ad.Name = Regex.Replace(attrName, "^(Anchor-|ImportOnly-|ExportOnly-)", "", RegexOptions.IgnoreCase);

        //                        ad.IsAnchor = p.Name.StartsWith("anchor-", StringComparison.OrdinalIgnoreCase);
        //                        ad.ImportOnly = p.Name.StartsWith("importonly-", StringComparison.OrdinalIgnoreCase);
        //                        ad.ExportOnly = p.Name.StartsWith("exportonly-", StringComparison.OrdinalIgnoreCase);
        //                        ad.IsMultiValue = p.Name.EndsWith("[]", StringComparison.OrdinalIgnoreCase);

        //                        // get the attribute type without array notation and convert to lowercase and
        //                        // set ad.Type based on the dictionary mapping or default to AttributeType.String
        //                        string cleanedAttrType = attrType.Replace("[]", "").ToLower();
        //                        ad.Type = typeMappings.ContainsKey(cleanedAttrType) ? typeMappings[cleanedAttrType] : AttributeType.String;

        //                        Tracer.TraceInformation("name '{0}', isanchor: {1}, ismultivalue: {2}, importonly: {3}, exportonly: {4}, type: {5}", ad.Name, ad.IsAnchor, ad.IsMultiValue, ad.ImportOnly, ad.ExportOnly, ad.Type);
        //                        attrs.Add(ad);
        //                    }
        //                }
        //                if (string.IsNullOrEmpty(objectTypeName))
        //                {
        //                    Tracer.TraceError("missing-object-class");
        //                    // Simplified logging to avoid format string issues
        //                    try
        //                    {
        //                        Tracer.TraceError("schema-object-properties-found: " + obj.Properties.ToList().Count.ToString());
        //                        foreach (PSPropertyInfo prop in obj.Properties)
        //                        {
        //                            string propName = prop.Name ?? "(null)";
        //                            string propValue = prop.Value?.ToString() ?? "(null)";
        //                            Tracer.TraceError("schema-property: '" + propName + "' = '" + propValue + "'");
        //                        }
        //                    }
        //                    catch (Exception traceEx)
        //                    {
        //                        Tracer.TraceError("error-during-schema-property-logging", traceEx);
        //                    }
        //                    throw new NoSuchObjectTypeException("Schema script returned an object without the required 'objectClass|string' property. Please ensure your schema script returns objects with proper objectClass definitions.");
        //                }

        //                SchemaType objectClass = SchemaType.Create(objectTypeName, true);
        //                foreach (AttributeDefinition def in attrs)
        //                {
        //                    if (def.IsAnchor)
        //                    {
        //                        objectClass.Attributes.Add(SchemaAttribute.CreateAnchorAttribute(def.Name, def.Type));
        //                    }
        //                    else
        //                    {
        //                        var attrOperation = def.ExportOnly ? AttributeOperation.ExportOnly :
        //                                            def.ImportOnly ? AttributeOperation.ImportOnly : AttributeOperation.ImportExport;

        //                        if (def.IsMultiValue)
        //                        {
        //                            objectClass.Attributes.Add(SchemaAttribute.CreateMultiValuedAttribute(def.Name, def.Type, attrOperation));
        //                        }
        //                        else
        //                        {
        //                            objectClass.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute(def.Name, def.Type, attrOperation));
        //                        }
        //                    }
        //                }
        //                if (objectClass.AnchorAttributes.Count == 1)
        //                {
        //                    schema.Types.Add(objectClass);
        //                }
        //                else
        //                {
        //                    Tracer.TraceError("missing-anchor-definition-on-object");
        //                    throw new AttributeNotPresentException();
        //                }
        //            }
        //        }
        //        schemaResults.Clear();
        //        return schema;
        //    }
        //    catch (Exception ex)
        //    {
        //        Tracer.TraceError("getschema", ex);
        //        throw;
        //    }
        //    finally
        //    {
        //        Tracer.Exit("getschema");
        //    }
        //}

    }

}
