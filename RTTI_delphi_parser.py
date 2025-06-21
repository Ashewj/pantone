from core.RTTI_delphi_custom import *
from core.DelphiData import *

dfmFinder = DFMFinder("Project1.exe")
dfmList = dfmFinder.GetDFMList()
numOfDfms = len(dfmList)
delphiFormList = list()

for i, dfmEntry in enumerate(dfmList):
    __pe = dfmFinder.p()
    
    data = get_bytes(__pe, dfmEntry[0], dfmEntry[1])
    if data and (is_loaded(__pe, dfmEntry[0] + dfmEntry[1] - 1) or dfmEntry[1] == 10000000):
        dfmEntryParser = DFMParser(data, dfmEntry[1])
        if dfmEntryParser.CheckSignature():
            methodList = list()
            VMTAddr = 0
            delphiDFM = dfmEntryParser.ParseForm()

            try:
                delphiRTTI = DelphiClass(__pe, 0, delphiDFM.GetClassName())
                VMTAddr = delphiRTTI.GetVMTAddress()
                #if not (delphiRTTI.GetClassFullName()).startswith("VMT_"):
                delphiRTTI.MakeClass()
                methodList = delphiRTTI.GetMethods()

            except Exception as e:
                print(f"[WARNING] | {delphiDFM.GetClassName()} | {e}")

            delphiFormList.append((delphiDFM, methodList, VMTAddr))

        del dfmEntryParser

for delphiDFM, methodList, VMTAddr in delphiFormList:
    #print(delphiDFM.GetObjectName(), "|", delphiDFM)
    if 'Form1' in delphiDFM.GetObjectName():
        for object in delphiDFM.GetChildObjectList():
            if 'Button2' in object.GetObjectName():
                for prop in object.GetPropertyList():
                    if prop.GetTypeAsString() == "Ident" and prop.GetName().startswith("On"):
                        handler_name = prop.GetValue()
                        #print(f"[+] Found event: {prop.GetName()} -> {handler_name} | {methodList}")

                        #for iv in methodList:
                         #   print(iv)
                            #if method_name == handler_name:
                            #    print(f"[+] Jumping to method: {handler_name} at 0x{method_va:X}")
                            #    break