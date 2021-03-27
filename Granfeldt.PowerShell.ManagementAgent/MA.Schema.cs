using Microsoft.MetadirectoryServices;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text.RegularExpressions;

namespace Granfeldt
{
	public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
	{
		Collection<PSObject> schemaResults;
		string SchemaScript = null;

		class AttributeDefinition
		{
			public string Name { get; set; }
			public AttributeType Type { get; set; }
			public bool IsMultiValue { get; set; }
			public bool IsAnchor { get; set; }
		}

		Schema IMAExtensible2GetSchema.GetSchema(KeyedCollection<string, ConfigParameter> configParameters)
		{
			Tracer.Enter("getschema");
			try
			{
				Schema schema = Schema.Create();
				InitializeConfigParameters(configParameters);

				OpenRunspace();
				Command cmd = new Command(Path.GetFullPath(SchemaScript));
				cmd.Parameters.Add(new CommandParameter("Username", Username));
				cmd.Parameters.Add(new CommandParameter("Password", Password));
				cmd.Parameters.Add(new CommandParameter("Credentials", GetSecureCredentials(Username, SecureStringPassword)));

				cmd.Parameters.Add(new CommandParameter("UsernameAux", UsernameAux));
				cmd.Parameters.Add(new CommandParameter("PasswordAux", PasswordAux));
				cmd.Parameters.Add(new CommandParameter("CredentialsAux", GetSecureCredentials(UsernameAux, SecureStringPasswordAux)));

				cmd.Parameters.Add(new CommandParameter("ConfigurationParameter", ConfigurationParameter));

				schemaResults = InvokePowerShellScript(cmd, null);
				CloseRunspace();

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
								ad.Name = Regex.Replace(attrName, "^Anchor-", "", RegexOptions.IgnoreCase);
								ad.IsAnchor = p.Name.StartsWith("anchor-", StringComparison.OrdinalIgnoreCase);
								ad.IsMultiValue = p.Name.EndsWith("[]", StringComparison.OrdinalIgnoreCase);
								switch (attrType.Replace("[]", "").ToLower())
								{
									case "boolean":
										ad.Type = AttributeType.Boolean;
										break;
									case "binary":
										ad.Type = AttributeType.Binary;
										break;
									case "integer":
										ad.Type = AttributeType.Integer;
										break;
									case "reference":
										ad.Type = AttributeType.Reference;
										break;
									case "string":
										ad.Type = AttributeType.String;
										break;
									default:
										ad.Type = AttributeType.String;
										break;
								}
								Tracer.TraceInformation("name '{0}', isanchor: {1}, ismultivalue: {2}, type: {3}", ad.Name, ad.IsAnchor, ad.IsMultiValue, ad.Type.ToString());
								attrs.Add(ad);
							}
						}
						if (string.IsNullOrEmpty(objectTypeName))
						{
							Tracer.TraceError("missing-object-class");
							throw new Microsoft.MetadirectoryServices.NoSuchObjectTypeException();
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
								if (def.IsMultiValue)
								{
									objectClass.Attributes.Add(SchemaAttribute.CreateMultiValuedAttribute(def.Name, def.Type));
								}
								else
								{
									objectClass.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute(def.Name, def.Type));
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
							throw new Microsoft.MetadirectoryServices.AttributeNotPresentException();
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

	}

}
