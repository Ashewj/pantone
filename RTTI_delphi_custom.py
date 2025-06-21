import pefile
import psutil

def __va_to_offset(p: pefile.PE, va: int) -> int:
        return p.get_offset_from_rva(va - p.OPTIONAL_HEADER.ImageBase)

def is_loaded(p: pefile.PE, va: int) -> bool:
    try:
        offset = __va_to_offset(p, va)
        return offset < len(p.__data__)
    except Exception:
        return False
    
def Byte(p: pefile.PE, va: int) -> int:
    offset = __va_to_offset(p, va)
    return p.__data__[offset]

def Word(p: pefile.PE, va: int) -> int:
    offset = __va_to_offset(p, va)
    data = p.__data__[offset : offset + 2]
    return data[0] | (data[1] << 8)

def Dword(p: pefile.PE, va: int) -> int:
    offset = __va_to_offset(p, va)
    data = p.__data__[offset : offset + 4]
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)

def Qword(p: pefile.PE, va: int) -> int:
    offset = __va_to_offset(p, va)
    data = p.__data__[offset : offset + 8]
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24) | (data[4] << 32) | (data[5] << 40) | (data[6] << 48) | (data[7] << 56)

##############################################################################################################################

def MakeByte(p: pefile.PE, va: int) -> int:
    value = Byte(p, va)
    #print(f"[MakeByte] 0x{va:X}: {value:#04x}")
    return value

def MakeWord(p: pefile.PE, va: int) -> int:
    value = Word(p, va)
    #print(f"[MakeWord] 0x{va:X}: {value:#06x}")
    return value

def MakeDword(p: pefile.PE, va: int) -> int:
    value = Dword(p, va)
    #print(f"[MakeDword] 0x{va:X}: {value:#010x}")
    return value

def MakeQword(p: pefile.PE, va: int) -> int:
    value = Qword(p, va)
    #print(f"[MakeQword] 0x{va:X}: {value:#018x}")
    return value

##############################################################################################################################

def FixName(name: str) -> str:
    name = "".join(i for i in name if ord(i) < 128)
    for elem in [".", "<", ">", ":", ",", "%"]:
        if elem in name:
            name = name.replace(elem, "_")
    return name

def GetStr(p: pefile.PE, va: int, length: int = None) -> str:
    offset = __va_to_offset(p, va)
    data = p.__data__[offset:]
    if length is not None:
        data = data[:length]
    try:
        return data.split(b'\x00')[0].decode('utf-8', errors='ignore')
    except Exception:
        return ""

def GetStr_PASCAL(p: pefile.PE, va: int) -> str:
    strlen = Byte(p, va)
    return GetStr(p, va + 1, strlen)

def MakeStr(p: pefile.PE, start_va: int, end_va: int = None) -> str:
    offset = __va_to_offset(p, start_va)
    data = p.__data__[offset:]

    # If end_va not provided, find the null-terminator
    if end_va is None:
        string = data.split(b'\x00')[0]
    else:
        end_offset = __va_to_offset(p, end_va)
        string = p.__data__[offset:end_offset]

    try:
        decoded = string.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        decoded = "<invalid utf-8>"

    #print(f"[MakeStr] 0x{start_va:X}: '{decoded}'")
    return decoded

def MakeStr_PASCAL(p: pefile.PE, va: int) -> str:
    strlen = Byte(p, va)
    # Pascal string is length-prefixed and ends at va + 1 + strlen
    return MakeStr(p, va + 1, va + 1 + strlen)

named_addresses = {}  # global symbol table

def MakeName(addr: int, name: str) -> None:
    fixed_name = FixName(name)
    named_addresses[addr] = fixed_name
    #print(f"[MakeName] 0x{addr:X} -> {fixed_name}")

def get_name(addr: int) -> str:
    """Simulate ida_name.get_name outside of IDA."""
    return named_addresses.get(addr, f"sub_{addr:08X}")

def DemangleFuncName(funcAddr: int) -> str:
    funcName = get_name(funcAddr)

    if "@" in funcName:
        funcNameSplitted = funcName.split("$")
        names = funcNameSplitted[0]

        parameters = ""
        if "$" in funcName:
            parameters = funcNameSplitted[1]

        namesSplitted = names.split("@")

        if namesSplitted[-1] == "":
            if namesSplitted[-2] == "":
                print(f"[WARNING] FixFuncName: Unmangling error - {funcName}")
            elif parameters == "bctr":
                funcName = namesSplitted[-2] + "_Constructor"
            elif parameters == "bdtr":
                funcName = namesSplitted[-2] + "_Destructor"
            else:
                print(f"[WARNING] FixFuncName: Unmangling error - {funcName}")
        elif namesSplitted[-1] == "":
            funcName = namesSplitted[-3] + "_" + namesSplitted[-1]
        else:
            funcName = namesSplitted[-2] + "_" + namesSplitted[-1]

        MakeName(funcAddr, FixName(funcName))

    #print('TODO: Better get_name(funcAddr)')
    return get_name(funcAddr)

##############################################################################################################################

class DelphiClass(object):
    __CLASS_DESCRIPTION = [
        "SelfPtr",
        "IntfTable",
        "AutoTable",
        "InitTable",
        "TypeInfo",
        "FieldTable",
        "MethodTable",
        "DynamicTable",
        "ClassName",
        "InstanceSize",
        "Parent"
    ]

    def __init__(self, p, VMT_addr: int, className: str = str()) -> None:
        self.__pe = p
        self.__processorWordSize = GetProcessorWordSize(self.__pe)
        if VMT_addr == 0:
            self.__VMTaddr = self.__GetVMTAddrByName(className)
        else:
            self.__VMTaddr = VMT_addr

        if self.IsDelphiClass():
            self.__classInfo = self.GetClassInfo()

            """self.__fieldEnum = FieldEnum(
                self.__classInfo["Name"],
                self.__classInfo["FullName"]
            )

            self.__funcStruct = FuncStruct(
                self.__classInfo["Name"],
                self.__classInfo["FullName"]
            )

            self.__intfTable = IntfTable(self.__classInfo)
            self.__initTable = InitTable(self.__classInfo, self.__fieldEnum)

            self.__typeInfo = TypeInfo(
                self.__classInfo["Address"]["TypeInfo"],
                self.__fieldEnum
            )

            self.__fieldTable = FieldTable(self.__classInfo, self.__fieldEnum)
            self.__methodTable = MethodTable(self.__classInfo)
            self.__dynamicTable = DynamicTable(self.__classInfo)
            self.__VMTTable = VMTTable(self.__classInfo, self.__funcStruct)"""

    def GetClassInfo(self) -> dict[str, str | dict[str, int]]:
        classInfo = {}
        classInfo["Address"] = self.__GetAddressTable()
        classInfo["Name"] = self.__GetClassName()
        classInfo["FullName"] = self.__GetVMTClassName()
        return classInfo
    
    def GetVMTAddress(self) -> int:
        return self.__VMTaddr

    def GetClassName(self) -> str:
        return self.__classInfo["Name"]

    def GetClassFullName(self) -> str:
        return self.__classInfo["FullName"]

    def GetClassAddress(self) -> int:
        return self.__classInfo["Address"]["Class"]
    
    def GetMethods(self) -> list[tuple[str, int]]:
        return GetMethods(self.__pe, self.__classInfo["Address"]["MethodTable"])
    
    def MakeClass(self) -> None:
        #print(f"[INFO] Processing ashewj {self.__classInfo['FullName']}")

        self.__DeleteClassHeader()
        self.__MakeClassName()

        self.ResolveParent(self.__classInfo["Address"]["ParentClass"])

        """self.__intfTable.MakeTable()
        self.__initTable.MakeTable()
        self.__typeInfo.MakeTable()
        self.__fieldTable.MakeTable()
        self.__methodTable.MakeTable()
        self.__dynamicTable.MakeTable()
        self.__VMTTable.MakeTable()"""

        self.__MakeClassHeader()

    def IsDelphiClass(self) -> bool:
        if not is_loaded(self.__pe, self.__VMTaddr) or \
           self.__VMTaddr == -1 or \
           self.__VMTaddr == 0:
            return False

        vmtTableAddr = GetCustomWord(self.__pe, self.__VMTaddr, self.__processorWordSize)

        if vmtTableAddr == 0 or vmtTableAddr < self.__VMTaddr:
            return False

        offset = vmtTableAddr - self.__VMTaddr

        if offset % self.__processorWordSize != 0 or \
           offset / self.__processorWordSize > 30 or \
           offset / self.__processorWordSize < 5:
            return False

        return True
    
    def __GetVMTClassName(self) -> str:
        return ("VMT_"
                + ("%x" % self.__VMTaddr).upper()
                + "_"
                + self.__GetClassName())

    def __GetClassName(self) -> str:
        return FixName(GetStr_PASCAL(self.__pe, self.__GetClassNameAddr()))

    def __GetClassNameAddr(self) -> int:
        return GetCustomWord(self.__pe,
            self.__VMTaddr + 8 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetIntfTableAddr(self) -> int:
        return GetCustomWord(self.__pe,
            self.__VMTaddr + 1 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetAutoTableAddr(self) -> int:
        return GetCustomWord(self.__pe,
            self.__VMTaddr + 2 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetInitTableAddr(self) -> int:
        return GetCustomWord(self.__pe,
            self.__VMTaddr + 3 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetTypeInfoAddr(self) -> int:
        return GetCustomWord(self.__pe,
            self.__VMTaddr + 4 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetFieldTableAddr(self) -> int:
        return GetCustomWord(self.__pe,
            self.__VMTaddr + 5 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetMethodTableAddr(self) -> int:
        return GetCustomWord(self.__pe,
            self.__VMTaddr + 6 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetDynamicTableAddr(self) -> int:
        return GetCustomWord(self.__pe,
            self.__VMTaddr + 7 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetParentClassAddr(self) -> int:
        return GetCustomWord(self.__pe,
            self.__VMTaddr + 10 * self.__processorWordSize,
            self.__processorWordSize
        )

    def __GetAddressTable(self) -> dict[str, int]:
            addressTable = {}
            addressTable["Class"] = self.__VMTaddr
            addressTable["VMTTable"] = GetCustomWord(
                self.__pe,
                self.__VMTaddr,
                self.__processorWordSize
            )
            addressTable["ParentClass"] = self.__GetParentClassAddr()
            addressTable["IntfTable"] = self.__GetIntfTableAddr()
            addressTable["AutoTable"] = self.__GetAutoTableAddr()
            addressTable["InitTable"] = self.__GetInitTableAddr()
            addressTable["TypeInfo"] = self.__GetTypeInfoAddr()
            addressTable["FieldTable"] = self.__GetFieldTableAddr()
            addressTable["MethodTable"] = self.__GetMethodTableAddr()
            addressTable["DynamicTable"] = self.__GetDynamicTableAddr()
            addressTable["ClassName"] = self.__GetClassNameAddr()
            return addressTable

    def __FindRef_Dword(self, section, dwordToFind: int) -> int:
        stringToFind = dwordToFind.to_bytes(4, byteorder='little')
        return self.__pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + section.get_data().find(stringToFind)
    
    def __GetVMTAddrByName(self, className: str) -> int:
        stringToFind = bytes([0x07, len(className)]) + className.encode("ascii")
        for section in self.__pe.sections:
            addr = self.__pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + section.get_data().find(stringToFind)
            if addr != -1:
                addr += 2 + len(className)
                addr = self.__FindRef_Dword(section, GetCustomWord(self.__pe, addr, 4))
            return addr
    
    #####################################################################################################################

    def __DeleteClassHeader(self) -> None:
        debug = self
        #print('TODO: DeleteClass')
        """ida_bytes.del_items(
            self.__VMTaddr,
            ida_bytes.DELIT_DELNAMES,
            GetCustomWord(
                self.__VMTaddr,
                self.__processorWordSize
            ) - self.__VMTaddr
        )"""

    def __MakeClassHeader(self) -> None:
        addr = self.__VMTaddr
        endAddr = GetCustomWord(self.__pe, self.__VMTaddr, self.__processorWordSize)
        i = 0

        while addr < endAddr and i < 30:
            MakeCustomWord(self.__pe, addr, self.__processorWordSize)

            if addr < self.__VMTaddr + 11 * self.__processorWordSize:
                debug = self
                #print(f'TODO: set_cmt({self.__CLASS_DESCRIPTION[i]})') #ida_bytes.set_cmt(addr, self.__CLASS_DESCRIPTION[i], 0)
            else:
                DemangleFuncName(GetCustomWord(self.__pe, addr, self.__processorWordSize))

            addr += self.__processorWordSize
            i += 1

    def __MakeClassName(self) -> None:
        classNameAddr = self.__GetClassNameAddr()
        classNameLen = Byte(self.__pe, classNameAddr)
        
        """ida_bytes.del_items(
            classNameAddr,
            ida_bytes.DELIT_DELNAMES,
            classNameLen + 1
        )"""

        MakeStr_PASCAL(self.__pe, classNameAddr)
        MakeName(classNameAddr, self.__classInfo["Name"] + "_ClassName")
        MakeCustomWord(self.__pe, self.__VMTaddr, self.__processorWordSize)

        print(f'TODO: set_name({self.__classInfo["FullName"]})')
        """ida_name.set_name(
            self.__VMTaddr,
            self.__classInfo["FullName"],
            ida_name.SN_NOCHECK
        )"""

    def ResolveParent(self, parentClassAddr: int) -> None:
        if is_loaded(self.__pe, parentClassAddr) and \
           parentClassAddr != 0: #and not ida_name.get_name(parentClassAddr).startswith("VMT_")
            try:
                #print("__ResolveParent | ashewj MakeClass()")
                DelphiClass(self.__pe, parentClassAddr).MakeClass()
            except Exception as e:
                print(f"[ERROR] {e}")

def GetMethods(__pe, __tableAddr) -> list[tuple[str, int]]:
        methodList = list()
        if __tableAddr != 0:
            numOfEntries = Word(__pe, __tableAddr)
            addr = __tableAddr + 2
            for i in range(numOfEntries):
                methodAddr = GetCustomWord(__pe, addr + 2, GetProcessorWordSize(__pe))
                methodName = GetStr_PASCAL(__pe, addr + 2 + GetProcessorWordSize(__pe))
                addr += Word(__pe, addr)
                methodList.append((methodName, methodAddr))
        return methodList

def GetCustomWord(p: pefile.PE, addr: int, wordSize: int = 4) -> int:
    if wordSize == 8:
        return Qword(p, addr)
    elif wordSize == 4:
        return Dword(p, addr)
    else:
        raise Exception("Unsupported word size!")

def MakeCustomWord(p: pefile.PE, addr: int, wordSize: int = 4) -> None:
    if wordSize == 8:
        MakeQword(p, addr)
    elif wordSize == 4:
        MakeDword(p, addr)
    else:
        raise Exception("Unsupported word size!")
    
IMAGE_DIRECTORY_ENTRY_RESOURCE = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']

def get_process_path_by_name(process_name: str) -> str:
    for proc in psutil.process_iter(['name', 'exe']):
        if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
            return proc.info['exe']
    return None

def get_bytes(p, va: int, size: int) -> bytes:
    offset = __va_to_offset(p, va)
    return p.__data__[offset:offset + size]

def Is64bit(pe: pefile.PE) -> bool:
    return pe.FILE_HEADER.Machine == 0x8664  # IMAGE_FILE_MACHINE_AMD64

def Is32bit(pe: pefile.PE) -> bool:
    return pe.FILE_HEADER.Machine == 0x14c  # IMAGE_FILE_MACHINE_I386

def GetProcessorWordSize(pe: pefile.PE) -> int:
    if Is64bit(pe):
        return 8
    elif Is32bit(pe):
        return 4
    else:
        raise Exception("Unsupported word size!")

class DFMFinder:
    def __init__(self, process_name: str):
        self.__pe = None
        self.__rsrcSecAddr = self.__GetResourceSectionAddress(get_process_path_by_name(process_name))
        self.__DFMlist = list()
        self.__ExtractDFM()
    
    def p(self):
        return self.__pe

    def GetDFMList(self) -> list[tuple[int, int]]:
        return self.__DFMlist
    
    def __CheckDFMSignature(self, addr: int) -> bool:
        if chr(Byte(self.__pe, addr)) == "T" and \
           chr(Byte(self.__pe, addr + 1)) == "P" and \
           chr(Byte(self.__pe, addr + 2)) == "F" and \
           chr(Byte(self.__pe, addr + 3)) == "0":
            return True
        else:
            return False
        
    def __GetResourceSectionAddress(self, application_path) -> int:
        if application_path:
            self.__pe = pefile.PE(application_path)
            resourceDirectoryRVA = self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
            if resourceDirectoryRVA:
                return self.__pe.OPTIONAL_HEADER.ImageBase + resourceDirectoryRVA
        return 0

    def __GetRCDATAAddr(self) -> int:
        numOfDirEntries = self.__GetNumberOfDirEntries(self.__rsrcSecAddr)
        addr = self.__rsrcSecAddr + 16
        for i in range(numOfDirEntries):
            # RCDATA
            if Dword(self.__pe, addr) == 10 and Dword(self.__pe, addr + 4) & 0x80000000 != 0:
                return self.__rsrcSecAddr + (Dword(self.__pe, addr + 4) & 0x7FFFFFFF)
            addr += 8
        return 0
    
    def __GetNumberOfDirEntries(self, tableAddr: int) -> int:
        return Word(self.__pe, tableAddr + 12) + Word(self.__pe, tableAddr + 14)

    def __ExtractDFMFromResource(self) -> None:
        print("[INFO] Searching for DFM in resource section...")

        if self.__rsrcSecAddr == 0:
            print("[INFO] The resource directory is empty.")
            return
        
        if self.__rsrcSecAddr != -1:
            RCDATAaddr = self.__GetRCDATAAddr()
            
            if RCDATAaddr != 0:
                RCDATAaddrEntryCount = self.__GetNumberOfDirEntries(RCDATAaddr)
                addr = RCDATAaddr + 16

                for i in range(RCDATAaddrEntryCount):
                    if Dword(self.__pe, addr) & 0x80000000 != 0:
                        strAddr = (self.__rsrcSecAddr
                                   + (Dword(self.__pe, addr) & 0x7FFFFFFF))

                        if Dword(self.__pe, addr + 4) & 0x80000000 != 0:
                            dirTableAddr = (self.__rsrcSecAddr
                                            + (Dword(self.__pe, addr + 4) & 0x7FFFFFFF))

                            if self.__GetNumberOfDirEntries(dirTableAddr) == 1:
                                DFMDataAddr = (self.__pe.OPTIONAL_HEADER.ImageBase
                                               + Dword(self.__pe, self.__rsrcSecAddr
                                               + Dword(self.__pe, dirTableAddr + 20)))

                                DFMDataSizeAddr = (self.__rsrcSecAddr
                                                   + Dword(self.__pe, dirTableAddr + 20)
                                                   + 4)
                                DFMDataSize = Dword(self.__pe, DFMDataSizeAddr)

                                if self.__CheckDFMSignature(DFMDataAddr):
                                    self.__DFMlist.append((DFMDataAddr, DFMDataSize))
                    addr += 8
            else:
                print("[WARNING] The resource section seems to be corrupted!")
        else:
            print("[WARNING] The resource section not found! Make sure the resource section is loaded correctly.")

    def __ExtractDFMFromBinary(self):
        print("[INFO] Searching for DFM in loaded binary...")

        self.__DFMlist = list()
        startAddr = 0
        counter = 0
        
        while True:
            # 0x0TPF0
            #dfmAddr = find_bytes(rb'.\x54\x50\x46\x30', startAddr)
            dfmAddr = self.__pe.OPTIONAL_HEADER.ImageBase + startAddr.VirtualAddress + startAddr.get_data().find(rb'.\x54\x50\x46\x30')
            """print(dfmAddr)
            if dfmAddr == '0xffffffffffffffff' or dfmAddr == '0xffffffff':
                break

            if counter != 0 and Byte(self.__pe, dfmAddr + 5) != 0:  # FP
                print(f"[INFO] Found DFM: 0x{dfmAddr:x}")
                self.__DFMlist.append((dfmAddr + 1, 10000000))

            counter += 1
            startAddr = dfmAddr + 1"""
        
    def __ExtractDFM(self) -> None:
        self.__ExtractDFMFromResource()

        #if len(self.__DFMlist) == 0:
        #    self.__ExtractDFMFromBinary()

        if len(self.__DFMlist) == 0:
            print("[INFO] No DFM found.")

    