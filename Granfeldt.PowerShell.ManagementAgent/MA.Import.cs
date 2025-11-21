using Microsoft.MetadirectoryServices;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text.RegularExpressions;

namespace Granfeldt
{
    public partial class PowerShellManagementAgent : IDisposable, IMAExtensible2GetCapabilities, IMAExtensible2GetSchema, IMAExtensible2GetParameters, IMAExtensible2CallImport, IMAExtensible2CallExport, IMAExtensible2Password
    {
        Hashtable objectTypeAnchorAttributeNames = new Hashtable();

        OperationType importOperationType;
        int ImportRunStepPageSize;
        bool MoreToImport = true;
        object returnedCustomData = "";
        object pageToken;
        int ImportPageNumber = 0;

        List<PSObject> importResults;
        List<CSEntryChange> csentryqueue = new List<CSEntryChange>();

        public int ImportDefaultPageSize => 100;
        public int ImportMaxPageSize => 10000;

        Schema schema;
        PSObject schemaPSObject;

        public void InitializeSchemaVariables(Schema Schema)
        {
            if (Schema == null) return;
            schema = Schema;

            schemaPSObject = new PSObject();
            foreach (SchemaType type in schema.Types)
            {
                PSObject typeObj = new PSObject();
                typeObj.Members.Add(new PSNoteProperty("ObjectType", type.Name));
                typeObj.Members.Add(new PSNoteProperty("PossibleDNComponentsForProvisioning", type.PossibleDNComponentsForProvisioning));
                PSObject attrObj = new PSObject();
                foreach (SchemaAttribute attr in type.AnchorAttributes)
                {
                    Tracer.TraceInformation("{0}-anchor-attribute {1} [{2}]", type.Name, attr.Name, attr.DataType);
                    attrObj.Members.Add(new PSNoteProperty(attr.Name, attr));
                }
                typeObj.Members.Add(new PSNoteProperty("Anchors", attrObj));

                attrObj = new PSObject();
                foreach (SchemaAttribute attr in type.Attributes)
                {
                    Tracer.TraceInformation("{0}-attribute {1} [{2}]", type.Name, attr.Name, attr.DataType);
                    attrObj.Members.Add(new PSNoteProperty(attr.Name, attr));
                }
                typeObj.Members.Add(new PSNoteProperty("Attributes", attrObj));

                // add to general schema object
                schemaPSObject.Members.Add(new PSNoteProperty(type.Name, typeObj));
            }
        }

        public OpenImportConnectionResults OpenImportConnection(System.Collections.ObjectModel.KeyedCollection<string, ConfigParameter> configParameters, Schema types, OpenImportConnectionRunStep openImportRunStep)
        {
            Tracer.Enter("openimportconnection");
            try
            {
                Tracer.TraceInformation("getting-schema");
                try
                {
                    foreach (SchemaType type in types.Types)
                    {
                        foreach (SchemaAttribute attr in type.AnchorAttributes)
                        {
                            objectTypeAnchorAttributeNames.Add(type.Name, attr.Name);
                        }
                    }
                    InitializeSchemaVariables(types);
                }
                catch (Exception ex)
                {
                    Tracer.TraceError("getting-schema", ex);
                }
                finally
                {
                    Tracer.TraceInformation("got-schema");
                }

                InitializeConfigParameters(configParameters);
                EnsurePowerShellEngine();

                Tracer.TraceInformation("resetting-pipeline-results-and-counters");
                importResults = new List<PSObject>();
                pageToken = "";
                ImportPageNumber = 0;

                OpenImportConnectionResults oicr = new OpenImportConnectionResults();
                ImportRunStepPageSize = openImportRunStep.PageSize;
                Tracer.TraceInformation("openimportrunstep-pagesize '{0}'", ImportRunStepPageSize);

                oicr.CustomData = openImportRunStep.ImportType == OperationType.Full ? "" : openImportRunStep.CustomData;
                Tracer.TraceInformation("openimportrunstep-customdata '{0}'", oicr.CustomData);

                importOperationType = openImportRunStep.ImportType;
                Tracer.TraceInformation("openimportrunstep-importtype '{0}'", importOperationType);

                return oicr;
            }
            catch (Exception ex)
            {
                Tracer.TraceError("openimportconnection", ex);
                throw;
            }
            finally
            {
                Tracer.Exit("openimportconnection");
            }
        }
        public GetImportEntriesResults GetImportEntries(GetImportEntriesRunStep importRunStep)
        {
            Tracer.Enter("getimportentries");
            try
            {
                #region call import script

                // if results is null, then this is the first time that we're called, 
                // so call script and get pipeline object and custom data
                Tracer.TraceInformation("more-to-import '{0}'", MoreToImport);

                if (MoreToImport)
                {
                    ImportPageNumber++;
                    MoreToImport = false; // make sure we set more-to-import to false; could be overwritten further down if pagedimports is true, though

                    // on first call, we set customdata to value from last successful run
                    returnedCustomData = importRunStep.CustomData;

                    Dictionary<string, object> parameters = GetDefaultScriptParameters();
                    parameters.Add("OperationType", importOperationType.ToString());
                    parameters.Add("UsePagedImport", usePagedImport);
                    parameters.Add("PageSize", ImportRunStepPageSize);
                    parameters.Add("ImportPageNumber", ImportPageNumber);
                    parameters.Add("Schema", schemaPSObject);


                    Tracer.TraceInformation("setting-custom-data '{0}'", importRunStep.CustomData);
                    engine.SetVariable("RunStepCustomData", importRunStep.CustomData);
                    Tracer.TraceInformation("setting-page-token '{0}'", pageToken);
                    engine.SetVariable("PageToken", pageToken);

                    importResults = engine.InvokeCommand(Path.GetFullPath(importScriptPath), parameters, null).ToList();

                    returnedCustomData = engine.GetVariable("RunStepCustomData");
                    pageToken = engine.GetVariable("PageToken");

                    Tracer.TraceInformation("page-token-returned '{0}'", pageToken == null ? "(null)" : pageToken);
                    Tracer.TraceInformation("custom-data returned '{0}'", returnedCustomData);
                    Tracer.TraceInformation("number-of-object(s)-in-pipeline {0:n0}", importResults.Count);

                    if (usePagedImport)
                    {
                        object moreToImportObject = engine.GetVariable("MoreToImport");
                        if (moreToImportObject == null)
                        {
                            Tracer.TraceError("For paged imports, the global variable 'MoreToImport' must be set to 'true' or 'false'");
                        }
                        else
                        {
                            Tracer.TraceInformation("MoreToImport-value-returned '{0}'", moreToImportObject);
                            if (bool.TryParse(moreToImportObject == null ? bool.FalseString : moreToImportObject.ToString(), out MoreToImport))
                            {
                                Tracer.TraceInformation("paged-import-setting-MoreToImport-to '{0}'", MoreToImport);
                            }
                            else
                            {
                                Tracer.TraceError("Value returned in MoreToImport must be a boolean with value of 'true' or 'false'");
                            }
                        }
                    }
                    else
                    {
                        MoreToImport = false;
                        Tracer.TraceInformation("non-paged-import-setting-MoreToImport-to '{0}'", MoreToImport);
                    }

                }
                #endregion

                #region parse returned objects
                if (importResults != null && importResults.Count > 0)
                {
                    List<PSObject> importResultsBatch = importResults.Take(ImportRunStepPageSize).ToList();
                    if (importResults.Count > ImportRunStepPageSize)
                    {
                        importResults.RemoveRange(0, importResultsBatch.Count);
                    }
                    else
                    {
                        importResults.Clear();
                    }
                    Tracer.TraceInformation("converting-objects-to-csentrychange {0:n0}", importResultsBatch.Count);
                    foreach (PSObject obj in importResultsBatch)
                    {
                        HashSet<AttributeDefinition> attrs = new HashSet<AttributeDefinition>();

                        Tracer.TraceInformation("start-connector-space-object");
                        try
                        {
                            CSEntryChange csobject = CSEntryChange.Create();

                            if (obj.BaseObject.GetType() != typeof(System.Collections.Hashtable))
                            {
                                Tracer.TraceWarning("invalid-object-in-pipeline '{0}'", 1, obj.BaseObject.GetType());
                                continue;
                            }

                            object AnchorValue = null;
                            string AnchorAttributeName = null;
                            string objectDN = null;
                            string objectClass = ""; // should be string to prevent null exceptions
                            string changeType = null;
                            string ErrorName = null;
                            string ErrorDetail = null;
                            MAImportError ImportErrorType = MAImportError.Success; // assume no error
                            Hashtable hashTable = (Hashtable)obj.BaseObject;

                            #region get control values
                            Tracer.TraceInformation("start-getting-control-values");
                            foreach (string key in hashTable.Keys)
                            {
                                if (key.Equals(Constants.ControlValues.ObjectClass, StringComparison.OrdinalIgnoreCase) || key.Equals(Constants.ControlValues.ObjectClassEx, StringComparison.OrdinalIgnoreCase))
                                {
                                    objectClass = (string)hashTable[key];
                                    Tracer.TraceInformation("got-objectclass {0}, {1}", objectClass, key);
                                    continue;
                                }
                                if (key.Equals(Constants.ControlValues.DN, StringComparison.OrdinalIgnoreCase))
                                {
                                    objectDN = (string)hashTable[key];
                                    Tracer.TraceInformation("got-dn {0}, {1}", objectDN, key);
                                    continue;
                                }
                                if (key.Equals(Constants.ControlValues.ChangeType, StringComparison.OrdinalIgnoreCase) || key.Equals(Constants.ControlValues.ChangeTypeEx, StringComparison.OrdinalIgnoreCase))
                                {
                                    changeType = (string)hashTable[key];
                                    Tracer.TraceInformation("got-changetype {0}, {1}", changeType, key);
                                    continue;
                                }
                                if (key.Equals(Constants.ControlValues.ErrorName, StringComparison.OrdinalIgnoreCase))
                                {
                                    ErrorName = (string)hashTable[key];
                                    Tracer.TraceInformation("got-errorname {0}, {1}", ErrorName, key);
                                    continue;
                                }
                                if (key.Equals(Constants.ControlValues.ErrorDetail, StringComparison.OrdinalIgnoreCase))
                                {
                                    ErrorDetail = (string)hashTable[key];
                                    Tracer.TraceInformation("got-errordetail {0}, {1}", ErrorDetail, key);
                                    continue;
                                }
                            }

                            if (string.IsNullOrEmpty(objectClass))
                            {
                                Tracer.TraceError("missing-objectclass");
                                ImportErrorType = MAImportError.ImportErrorCustomContinueRun;
                                ErrorName = "missing-objectclass-value";
                                ErrorDetail = "No value provided for objectclass attribute";
                            }
                            else
                            {
                                AnchorAttributeName = objectTypeAnchorAttributeNames[objectClass] == null ? "" : (string)objectTypeAnchorAttributeNames[objectClass];
                                if (string.IsNullOrEmpty(AnchorAttributeName))
                                {
                                    ImportErrorType = MAImportError.ImportErrorInvalidAttributeValue;
                                    ErrorName = "invalid-objecttype";
                                    ErrorDetail = "Objecttype not defined in schema";
                                }

                                foreach (string key in hashTable.Keys)
                                {
                                    if (key.Equals(AnchorAttributeName, StringComparison.OrdinalIgnoreCase))
                                    {
                                        AnchorValue = hashTable[key];
                                        Tracer.TraceInformation("got-anchor {0}, {1}", AnchorValue, key);
                                        break;
                                    }
                                }
                            }
                            Tracer.TraceInformation("end-getting-control-values");

                            if (AnchorValue == null && string.IsNullOrEmpty(ErrorName))
                            {
                                Tracer.TraceError("missing-anchor");
                                ImportErrorType = MAImportError.ImportErrorCustomContinueRun;
                                ErrorName = "missing-anchor-value";
                                ErrorDetail = "No value provided for anchor attribute";
                            }

                            if (AnchorValue != null && string.IsNullOrEmpty(objectDN))
                            {
                                Tracer.TraceInformation("setting-anchor-as-dn {0}", AnchorValue);
                                objectDN = AnchorValue.ToString();
                            }

                            if (!string.IsNullOrEmpty(ErrorName))
                            {
                                ImportErrorType = MAImportError.ImportErrorCustomContinueRun;
                                if (string.IsNullOrEmpty(ErrorDetail))
                                {
                                    ErrorDetail = "No error details provided";
                                }
                            }
                            #endregion control values

                            #region return invalid object
                            if (ImportErrorType != MAImportError.Success)
                            {
                                Tracer.TraceInformation("returning-invalid-object");
                                if (AnchorValue != null)
                                {
                                    csobject.AnchorAttributes.Add(AnchorAttribute.Create(AnchorAttributeName, AnchorValue));
                                }
                                csobject.ObjectModificationType = ObjectModificationType.Add;
                                if (!string.IsNullOrEmpty(objectClass))
                                {
                                    try
                                    {
                                        csobject.ObjectType = objectClass;
                                    }
                                    catch (NoSuchObjectTypeException otEx)
                                    {
                                        Tracer.TraceError("no-such-object '{0}'", otEx);
                                    }
                                }
                                if (!string.IsNullOrEmpty(objectClass))
                                {
                                    csobject.DN = objectDN;
                                }
                                Tracer.TraceError("invalid-object dn: {0}, type: {1}, name: {2}, details: {3} ", objectDN, ImportErrorType, ErrorName, ErrorDetail);
                                csobject.ErrorCodeImport = ImportErrorType;
                                csobject.ErrorName = ErrorName;
                                csobject.ErrorDetail = ErrorDetail;
                                csentryqueue.Add(csobject);
                                continue;
                            }
                            #endregion

                            #region return deleted object
                            // we must set ObjectModificationType before any other attributes; otherwise it will default to 'Add'
                            if (!string.IsNullOrEmpty(changeType) && changeType.Equals("delete", StringComparison.OrdinalIgnoreCase))
                            {
                                Tracer.TraceInformation("returning-deleted-object");
                                Tracer.TraceInformation("change-type {0}", changeType);
                                csobject.ObjectModificationType = ObjectModificationType.Delete;
                                csobject.ObjectType = objectClass;
                                csobject.DN = objectDN;

                                // we need to get the object anchor value for the deletion
                                csobject.AnchorAttributes.Add(AnchorAttribute.Create(AnchorAttributeName, AnchorValue));
                                csentryqueue.Add(csobject);
                                continue;
                            }
                            #endregion

                            #region returned live object
                            Tracer.TraceInformation("returning-valid-object");
                            csobject.ObjectModificationType = ObjectModificationType.Add;
                            csobject.ObjectType = objectClass;
                            csobject.DN = objectDN;
                            csobject.AnchorAttributes.Add(AnchorAttribute.Create(AnchorAttributeName, AnchorValue));
                            foreach (string key in hashTable.Keys)
                            {
                                try
                                {
                                    if (Regex.IsMatch(key, string.Format(@"^(objectClass|\[objectclass\]|changeType|\[changetype\]|\[DN\]|\[ErrorName\]|\[ErrorDetail\]|{0})$", AnchorAttributeName), RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                    {
                                        Tracer.TraceInformation("skip-control-value {0}", key);
                                        continue;
                                    }
                                    if (hashTable[key] == null)
                                    {
                                        Tracer.TraceInformation("skip-null-value-for '{0}'", key);
                                        continue;
                                    }
                                    SchemaAttribute sa = schema.Types[objectClass].Attributes[key];
                                    Tracer.TraceInformation("attribute: {0} (type {1}, {2}): '{3}'", key, sa.DataType, sa.IsMultiValued ? "multi-value" : "single-value", hashTable[key]);
                                    if (sa.IsMultiValued)
                                    {
                                        //Tracer.TraceInformation("add-multivalue '{0}' [{1}]", key, hashTable[key].GetType());
                                        List<object> mvs = new List<object>();
                                        if (hashTable[key].ToString().EndsWith("[]"))
                                        {
                                            mvs.AddRange((object[])hashTable[key]);
                                        }
                                        else
                                        {
                                            mvs.Add(hashTable[key]);
                                        }
                                        csobject.AttributeChanges.Add(AttributeChange.CreateAttributeAdd(key, mvs));
                                    }
                                    else
                                    {
                                        csobject.AttributeChanges.Add(AttributeChange.CreateAttributeAdd(key, hashTable[key]));
                                    }

                                }
                                catch (KeyNotFoundException keyexception)
                                {
                                    Tracer.TraceError("attribute-is-not-defined-for '{0}' / '{1}' ({2})", key, objectClass, keyexception.ToString());
                                }
                            }
                            #endregion

                            if (csobject.ErrorCodeImport != MAImportError.Success)
                            {
                                Tracer.TraceError("defective-csentrychange id: {0}, dn: {1}, errorcode: {2}, error: {3}, details: {4}", csobject.Identifier, csobject.DN, csobject.ErrorCodeImport, csobject.ErrorName, csobject.ErrorDetail);
                            }
                            Tracer.TraceInformation("returning-csentry dn: {0}, id: {1}", csobject.DN, csobject.Identifier);
                            csentryqueue.Add(csobject);
                        }
                        catch (Exception ex)
                        {
                            Tracer.TraceError("creating-csentrychange", ex);
                        }
                        finally
                        {
                            Tracer.TraceInformation("end-connector-space-object");
                        }
                    }
                    // clearing results for next loop
                    importResultsBatch.Clear();
                }
                #endregion

                #region dequeue csentries

                GetImportEntriesResults importReturnInfo = null;

                Tracer.TraceInformation("total-import-object(s)-left {0:n0}", importResults.Count);
                Tracer.TraceInformation("total-connector-space-object(s)-left {0:n0}", csentryqueue.Count);

                List<CSEntryChange> batch = csentryqueue.Take(ImportRunStepPageSize).ToList();
                if (csentryqueue.Count > ImportRunStepPageSize)
                {
                    csentryqueue.RemoveRange(0, batch.Count);
                }
                else
                {
                    csentryqueue.Clear();
                }
                importReturnInfo = new GetImportEntriesResults();
                importReturnInfo.MoreToImport = MoreToImport || importResults.Count > 0 || (csentryqueue.Count > 0);
                importReturnInfo.CustomData = returnedCustomData == null ? "" : returnedCustomData.ToString();
                importReturnInfo.CSEntries = batch;

                Tracer.TraceInformation("should-return-for-more {0}", importReturnInfo.MoreToImport);
                Tracer.TraceInformation("custom-data '{0}'", importReturnInfo.CustomData);
                Tracer.TraceInformation("connector-space-object(s)-returned {0:n0}", importReturnInfo.CSEntries.Count);

                return importReturnInfo;

                #endregion
            }
            catch (Exception ex)
            {
                Tracer.TraceError("getimportentries", ex);
                throw new TerminateRunException(ex.Message);
            }
            finally
            {
                Tracer.Exit("getimportentries");
            }
        }
        public CloseImportConnectionResults CloseImportConnection(CloseImportConnectionRunStep importRunStep)
        {
            Tracer.Enter("closeimportconnectionresults");
            try
            {
                CloseImportConnectionResults cicr = new CloseImportConnectionResults();
                Tracer.TraceInformation("custom-data {0}", importRunStep.CustomData);
                Tracer.TraceInformation("close-reason {0}", importRunStep.Reason);
                if (importRunStep.Reason == CloseReason.Normal)
                {
                    cicr.CustomData = importRunStep.CustomData;
                }
                Dispose();
                return cicr;
            }
            catch (AppDomainUnloadedException)
            {
                // AppDomain is unloading, return minimal results
                return new CloseImportConnectionResults();
            }
            catch (Exception ex)
            {
                Tracer.TraceError("closeimportconnection", ex);
                throw;
            }
            finally
            {
                Tracer.Exit("closeimportconnectionresults");
            }
        }

    }

}
