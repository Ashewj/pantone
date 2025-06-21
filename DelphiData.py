from __future__ import annotations
import hashlib
import os
import struct

PropertyTypes = ["Null", "List", "Int8", "Int16", "Int32", "Extended",
                 "String", "Ident", "False", "True", "Binary", "Set",
                 "LString", "Nil", "Collection", "Single", "Currency", "Date",
                 "WString", "Int64", "UTF8String", "Double"]

class DelphiProperty(object):

    def __init__(
            self,
            name: str,
            propType: int,
            value: bytes | int | list | str,
            parentObj: DelphiObject) -> None:
        self.__type = propType
        self.__name = name
        self.__value = value
        self.__parentObj = parentObj

    def GetType(self) -> int:
        return self.__type

    def GetTypeAsString(self) -> str:
        return PropertyTypes[self.__type]

    def GetName(self) -> str:
        return self.__name

    def GetParentObjName(self) -> str:
        return self.__parentObj.GetObjectName()

    def GetParentClassName(self) -> str:
        return self.__parentObj.GetClassName()

    def GetValue(self) -> bytes | int | list | str:
        return self.__value

    def GetValueAsString(self, flag: int = 0) -> None:
        return self.__PrintValue(self.__value, self.__type, flag)

    def PrintPropertyInfo(self, indentation: str) -> None:
        """Print Property Info"""

        # Binary
        if self.__type == 10:
            print(f"{indentation}{self.__name} = Binary data ... ({PropertyTypes[self.__type]})")
        else:
            print(f"{indentation}{self.__name} = {self.__PrintValue(self.__value, self.__type)} ({PropertyTypes[self.__type]})")

    def __PrintValue(
            self,
            data: bytes | int | list | str,
            dataType: int,
            flag: int = 0) -> str:
        match dataType:
            case 0:
                # "Null"
                return "Null"
            case 1:
                # "List"
                return self.__PrintList(data)
            case 2:
                # "Int8"
                return str(data)
            case 3:
                # "Int16"
                return str(data)
            case 4:
                # "Int32"
                return str(data)
            case 5:
                # "Extended"
                return self.__PrintExtended(data)
            case 6:
                # "String"
                return self.__PrintString(data)
            case 7:
                # "Ident"
                return data.decode()
            case 8:
                # "False"
                return "False"
            case 9:
                # "True"
                return "True"
            case 10:
                # "Binary"
                return self.__PrintBinary(data, flag)
            case 11:
                # "Set"
                return self.__PrintSet(data)
            case 12:
                # "LString"
                return self.__PrintString(data)
            case 13:
                # "Nil"
                return "Nil"
            case 14:
                # "Collection"
                return self.__PrintCollection(data)
            case 15:
                # "Single"
                return str(struct.unpack("f", data)[0])
            case 16:
                # "Currency"
                return str(struct.unpack("d", data)[0])
            case 17:
                # "Date"
                return str(struct.unpack("d", data)[0])
            case 18:
                # "WString"
                return self.__PrintWString(data)
            case 19:
                # "Int64"
                return str(struct.unpack("q", data)[0])
            case 20:
                # "UTF8String"
                return self.__PrintString(data)
            case 21:
                # "Double"
                return str(struct.unpack("d", data)[0])
            case _:
                return ""

    def __PrintExtended(self, data: bytes) -> str:
        strValue = str()

        for a in data:
            strValue += "%02X" % (a)

        return strValue

    def __PrintBinary(self, data: bytes, flag: int = 0) -> str:
        if flag == 1:
            hashSha1 = hashlib.sha1()
            hashSha1.update(data)
            return hashSha1.hexdigest().upper()
        #else:
           # return self.__SaveDataToFile(data)

    def __PrintList(self, listData: list) -> str:
        if len(listData) == 0:
            strValue = "[]"
        else:
            strValue = "["

            for item in listData:
                strValue += self.__PrintValue(item[0], item[1]) + ", "

            strValue = strValue[:-2] + "]"

        return strValue

    def __PrintCollection(self, data: list) -> str:
        if len(data) == 0:
            return "<>"
        else:
            strValue = "<"

            for collectionElem in data:
                if collectionElem[0] is not None:
                    strValue += " [" + str(collectionElem[0]) + "]: "

                if len(collectionElem[1]) != 0:
                    for attrElem in collectionElem[1]:
                        strValue += (attrElem[0]
                                     + "="
                                     + self.__PrintValue(attrElem[1], attrElem[2])
                                     + " | ")

                    strValue = strValue[:-3]

                strValue += ", "

            return strValue[:-2] + ">"

    def __PrintSet(self, data: list) -> str:
        if len(data) == 0:
            return "()"
        else:
            strValue = str()

            for elem in data:
                strValue += elem.decode() + ", "

            strValue = "(" + strValue[: -2] + ")"
            return strValue

    def __PrintString(self, rawdata: bytes) -> str:
        if len(rawdata) == 0:
            strValue = "\'\'"
        else:
            strValue = str(rawdata)[1:]

        return strValue

    def __PrintWString(self, rawData: bytes) -> str:
        data = list()

        for i in range(len(rawData) // 2):
            value = rawData[i*2] + (rawData[i*2 + 1] << 8)
            data.append(value)

        if len(data) == 0:
            strValue = "\'\'"
        else:
            strValue = "\'"

            for a in data:
                if a > 31 and a < 127:
                    strValue += str(chr(a))
                else:
                    strValue += "\\u%04x" % (a)

            strValue += "\'"

        return strValue

    """ 
    def __SaveDataToFile(self, data: bytes) -> str:
        ###
        Save extracted data to folder, the folder name is derived from the
        file name of the binary. i.e: file.exe -> _extracted_file_exe

        Args:
            data (bytes): data to save to the folder.

        Returns:
            path (str): return path of the folder.
        ###
        binaryFileName = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if binaryFileName.endswith(".idb") or binaryFileName.endswith(".i64"):
            binaryFileName = binaryFileName[:-4]
        binaryFileName = binaryFileName[binaryFileName.rfind(os.path.sep) + 1:]

        dataDir = os.path.abspath(idautils.GetIdbDir())
        if not os.path.isdir(dataDir):
            print(f"[ERROR] No such directory: \"{dataDir}\". Trying to create it...")

            try:
                os.mkdir(dataDir)
            except FileNotFoundError:
                print(f"Failed to create directory: \"{dataDir}\". Extracted file not saved!")
                return ""

        dataDir = os.path.join(
            dataDir,
            "_extracted_" + binaryFileName.replace(".", "_")
        )

        if not os.path.isdir(dataDir):
            os.mkdir(dataDir)

        data, ext = self.__PreprocessData(data)
        fileName = self.__GetFileName() + ext

        filePath = os.path.join(dataDir, fileName)
        with open(filePath, "wb") as f:
            print(f"[INFO] Saving file \"{filePath}\"")
            f.write(data)

        retPath = ("\".\\_extracted_"
                   + binaryFileName.replace(".", "_")
                   + "\\"
                   + fileName
                   + "\"")

        return retPath
    """ 

    def __PreprocessData(self, data: bytes) -> tuple[bytes, str]:
        ext = ".bin"
        signature = data[:32]

        if b"TBitmap" in signature:
            data = data[12:]
            ext = ".bmp"
        elif b"TJPEGImage" in signature:
            data = data[15:]
            ext = ".jpeg"
        elif b"TWICImage" in signature:
            data = data[10:]
            ext = ".tif"
        elif b"TPngImage" in signature:
            data = data[10:]
            ext = ".png"
        elif b"TPNGGraphic" in signature:
            data = data[16:]
            ext = ".png"
        elif b"TPNGObject" in signature:
            data = data[11:]
            ext = ".png"
        elif signature[1:4] == b"PNG":
            ext = ".png"
        elif b"TGIFImage" in signature:
            data = data[10:]
            ext = ".gif"
        elif signature[28:31] == b"BM6":
            data = data[28:]
            ext = ".bmp"
        elif signature[4:6] == b"BM":
            flag = True

            for i in range(4):
                if data[i] != data[i + 6]:
                    flag = False

            if flag:
                data = data[4:]
                ext = ".bmp"

        return data, ext

    def __GetFileName(self) -> str:
        parentObj = self.__parentObj
        fileName = str()

        while parentObj is not None:
            fileName = parentObj.GetObjectName()[:15] + "_" + fileName
            parentObj = parentObj.GetParentObject()

        return fileName[:len(fileName)-1]

class DelphiObject(object):

    def __init__(
            self,
            className: str,
            objName: str,
            parentObj: DelphiObject | None) -> None:
        self.__className = className
        self.__objectName = objName
        self.__listOfChildrenObjects = list()
        self.__listOfProperties = list()
        self.__parentObj = parentObj

    def GetParentObject(self) -> DelphiObject | None:
        return self.__parentObj

    def GetObjectName(self) -> str:
        return self.__objectName

    def SetObjectName(self, objName: str) -> None:
        self.__objectName = objName

    def GetClassName(self) -> str:
        return self.__className

    def SetClassName(self, className: str) -> None:
        self.__className = className

    def GetPropertyList(self) -> list[DelphiProperty]:
        return self.__listOfProperties

    def AddProperty(self, prop: DelphiProperty) -> None:
        self.__listOfProperties.append(prop)

    def GetChildObjectList(self) -> list[DelphiObject]:
        return self.__listOfChildrenObjects

    def AddChildObject(self, childObj: DelphiObject) -> None:
        self.__listOfChildrenObjects.append(childObj)

    def PrintObjectInfo(self, indentation: str = "") -> None:
        print(f"{indentation}object {self.__objectName}: {self.__className}")

        for prop in self.__listOfProperties:
            prop.PrintPropertyInfo(indentation + "   ")

        for obj in self.__listOfChildrenObjects:
            obj.PrintObjectInfo(indentation + "   ")

        print(f"{indentation} end")

class DFMParser(object):
    def __init__(self, data: bytes, dataSize: int) -> None:
        self.__resData = data
        self.__resDataSize = dataSize
        self.__resDataPos = 0

    def ParseForm(self) -> DelphiObject | None:
        if self.__ReadSignature():
            delphiForm = self.__ParseObject()
            return delphiForm
        return None

    def CheckSignature(self) -> bool:
        if self.__resDataSize < 4:
            return False
        return self.__resData.startswith(b"TPF0")

    def __ParseProperty(
            self,
            parentDelphiObj: DelphiObject) -> DelphiProperty | None:
        try:
            if self.__ReadRawData(1, 0)[0] == 0:
                self.__ReadByte()
                return None
        except Exception:
            return None

        propName = self.__ReadString().decode()
        propType = self.__ReadByte()

        if propName is None or propType is None:
            return None

        propValue = self.__ReadPropertyValue(propType)

        delphiProp = DelphiProperty(
            propName,
            propType,
            propValue,
            parentDelphiObj
        )
        parentDelphiObj.AddProperty(delphiProp)

        return delphiProp

    def __ParseObject(
            self,
            parentDelphiObj: DelphiObject | None = None
            ) -> DelphiObject | None:
        try:
            if self.__ReadRawData(1, 0)[0] == 0:
                self.__ReadByte()
                return None
        except Exception:
            return None

        if not self.__ReadPrefix():
            className = self.__ReadString().decode()
            objectName = self.__ReadString().decode()

            if className is not None and objectName is not None:
                childDelphiObj = DelphiObject(
                    className,
                    objectName,
                    parentDelphiObj
                )

                while self.__ParseProperty(childDelphiObj) is not None:
                    pass
                while self.__ParseObject(childDelphiObj) is not None:
                    pass

                if parentDelphiObj is not None:
                    parentDelphiObj.AddChildObject(childDelphiObj)

                return childDelphiObj
            else:
                raise Exception("ClassName or ObjName is None")

    def __ReadSignature(self) -> bool:
        return self.__ReadRawData(4) == b"TPF0"

    def __OutOfDataCheck(self, size: int) -> bool:
        if self.__resDataPos + size - 1 >= self.__resDataSize:
            raise Exception("DMF corrupted: No more data to read!")
        return False

    def __ReadRawData(self, size: int, shift: int = 1) -> bytes:
        if size < 0:
            size = 0

        self.__OutOfDataCheck(size)
        rawData = self.__resData[self.__resDataPos:self.__resDataPos+size]

        if shift == 1:
            self.__resDataPos += size

        return rawData

    def __ReadByte(self) -> int:
        return self.__ReadRawData(1)[0]

    def __ReadWord(self) -> int:
        rawData = self.__ReadRawData(2)
        value = 0

        for i in range(2):
            value += (rawData[i] << i*8)
        return value

    def __ReadDword(self) -> int:
        rawData = self.__ReadRawData(4)
        value = 0

        for i in range(4):
            value += (rawData[i] << i*8)
        return value

    def __ReadString(self) -> bytes:
        return self.__ReadRawData(self.__ReadByte())

    def __ReadLString(self) -> bytes:
        return self.__ReadRawData(self.__ReadDword())

    def __ReadWString(self) -> bytes:
        return self.__ReadRawData(self.__ReadDword() * 2)

    def __ReadData(self) -> bytes:
        return self.__ReadRawData(self.__ReadDword())

    def __ReadSingle(self) -> bytes:
        return self.__ReadRawData(4)

    def __ReadExtended(self) -> bytes:
        return self.__ReadRawData(10)

    def __ReadDouble(self) -> bytes:
        return self.__ReadRawData(8)

    def __ReadCurrency(self) -> bytes:
        return self.__ReadRawData(8)

    def __ReadDate(self) -> bytes:
        return self.__ReadRawData(8)

    def __ReadInt64(self) -> bytes:
        return self.__ReadRawData(8)

    def __ReadList(self) -> list:
        listElementType = self.__ReadByte()
        listElements = list()

        while listElementType != 0:
            listElements.append(
                (self.__ReadPropertyValue(listElementType), listElementType)
            )
            listElementType = self.__ReadByte()
        return listElements

    def __ReadSet(self) -> list:
        setElements = list()

        while True:
            elem = self.__ReadString()

            if len(elem) != 0:
                setElements.append(elem)
            else:
                break

        return setElements

    def __ReadCollection(self) -> list:
        collectionElements = list()

        while True:
            elementValue = None
            elementType = self.__ReadByte()

            if elementType == 0:
                break
            elif elementType == 2 or elementType == 3 or elementType == 4:
                elementValue = self.__ReadPropertyValue(elementType)
            elif elementType == 1:
                attrList = list()
                flag = True

                while flag:
                    attrName = self.__ReadString().decode()

                    if len(attrName) == 0:
                        flag = False
                    else:
                        attrType = self.__ReadByte()
                        attrList.append((
                            attrName,
                            self.__ReadPropertyValue(attrType),
                            attrType
                        ))
            else:
                raise Exception("Invalid collection format!")

            collectionElements.append((elementValue, attrList))

        return collectionElements

    def __ReadPrefix(self) -> bool:
        if self.__ReadRawData(1, 0)[0] & 0xf0 == 0xf0:
            prefix = self.__ReadByte()

            flags = prefix & 0x0f

            if flags > 7:
                raise Exception("Unsupported DFM Prefix.")

            if (flags & 2) != 0:
                propType = self.__ReadByte()

                if propType == 2 or propType == 3 or propType == 4:
                    self.__ReadPropertyValue(propType)
                else:
                    raise Exception("Unsupported DFM Prefix.")

        return False

    def __ReadPropertyValue(
            self,
            propType: int) -> bytes | int | list | str:
        match propType:
            # Null
            case 0: return "Null"
            # List
            case 1: return self.__ReadList()
            # Int8
            case 2: return self.__ReadByte()
            # Int16
            case 3: return self.__ReadWord()
            # Int32
            case 4: return self.__ReadDword()
            # Extended
            case 5: return self.__ReadExtended()
            # String
            case 6: return self.__ReadString()
            # Ident
            case 7: return self.__ReadString()
            # False
            case 8: return 0
            # True
            case 9: return 1
            # Binary
            case 10: return self.__ReadData()
            # Set
            case 11: return self.__ReadSet()
            # LString
            case 12: return self.__ReadLString()
            # Nil
            case 13: return "Nil"
            # Collection
            case 14: return self.__ReadCollection()
            # Single
            case 15: return self.__ReadSingle()
            # Currency
            case 16: return self.__ReadCurrency()
            # Date
            case 17: return self.__ReadDate()
            # WString
            case 18: return self.__ReadWString()
            # Int64
            case 19: return self.__ReadInt64()
            # UTF8String
            case 20: return self.__ReadLString()
            # Double
            case 21: return self.__ReadDouble()
            case _:
                raise Exception("Unsupported property type: " + str(propType))