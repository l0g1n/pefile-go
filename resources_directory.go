package pefile

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func (pe *PEFile) parseResourcesDirectory(rva, size uint32) error {
	fileOffset, err := pe.getOffsetFromRva(rva)
	if err != nil {
		return err
	}
	if fileOffset < pe.dataLen+size {
		retMap := map[string]interface{}{}
		//if pe.OptionalHeader64 != nil {
		//	pe.parseResources64(fileOffset, fileOffset, retMap, true)
		//} else {
		pe.parseResources(fileOffset, fileOffset, retMap, true)
		//}
		pe.Resources = retMap
	}
	return nil
}

func (pe *PEFile) parseResources64(resourceHeader, fileOffset uint32, retMap map[string]interface{}, bFirst bool) error {
	resourcesDesc := newResourceDirectory(fileOffset)
	if err := pe.readOffset(&resourcesDesc.Data, fileOffset); err != nil {
		return err
	}
	fileOffset += resourcesDesc.Size
	entryNum := resourcesDesc.Data.NumberOfIDEntries + resourcesDesc.Data.NumberOfNamedEntries
	for entryNum > 0 {
		dirEntry := newResourceDirectoryEntry(fileOffset)
		if err := pe.readOffset(&dirEntry.Data, fileOffset); err != nil {
			return err
		}
		//解析名称
		isNameString := ((uint64(dirEntry.Data.Name) & 0xffffffff) >> 0x1f) > 0
		nameOffset := uint32((uint64(dirEntry.Data.Name) & 0x7fffffff) >> 0x0)
		var name string
		if isNameString {
			//字符串类型名称
			startPos := resourceHeader + nameOffset
			lenbuff := bytes.NewBuffer(pe.data[startPos : startPos+2])
			var strLen uint16
			binary.Read(lenbuff, binary.LittleEndian, &strLen)
			buff := pe.data[startPos+2 : startPos+2+uint32(strLen*2)]
			var ascii []byte
			for i, v := range buff {
				if i%2 == 0 {
					ascii = append(ascii, v)
				}
			}
			name = string(ascii)
			//fmt.Println(string(ascii))
		} else {
			//序号类型名称
			name = fmt.Sprint(nameOffset)
			//第一层
			if bFirst {
				switch nameOffset {
				case 1:
					name = "RT_CURSOR"
				case 2:
					name = "RT_BITMAP"
				case 3:
					name = "RT_ICON"
				case 4:
					name = "RT_MENU"
				case 5:
					name = "RT_DIALOG"
				case 6:
					name = "RT_STRING"
				case 7:
					name = "RT_FONTDIR"
				case 8:
					name = "RT_FONT"
				case 9:
					name = "RT_ACCELERATOR"
				case 10:
					name = "RT_RCDATA"
				case 11:
					name = "RT_MESSAGETABLE"
				case 12:
					name = "RT_GROUP_CURSOR"
				case 14:
					name = "RT_GROUP_ICON"
				case 16:
					name = "RT_VERSION"
				case 17:
					name = "RT_DLGINCLUDE"
				case 19:
					name = "RT_PLUGPLAY"
				case 20:
					name = "RT_VXD"
				case 21:
					name = "RT_ANICURSOR"
				case 22:
					name = "RT_ANIICON"
				case 23:
					name = "RT_HTML"
				case 24:
					name = "RT_MANIFEST"
				}
			}
			//fmt.Printf("%d --> %d\n", entryNum, dirEntry.Data.Name)
			//fmt.Println(name)
		}
		//解析数据
		dataEntry := newResourceDataEntry(fileOffset)
		if err := pe.readOffset(&dataEntry.Data, fileOffset); err != nil {
			return err
		}
		isDir := ((uint64(dataEntry.Data.Size) & 0xffffffff) >> 0x1f) > 0
		offsetToDir := uint32((uint64(dataEntry.Data.Size) & 0x7fffffff) >> 0x0)
		//fmt.Printf("%t %x\n", isDir, offsetToDir)
		if isDir {
			//表示是目录
			rValue := map[string]interface{}{}
			pe.parseResources64(resourceHeader, resourceHeader+offsetToDir, rValue, false)
			retMap[name] = rValue
		} else {
			//表示是文件
			dataDir := newResourceDataDirectory(resourceHeader + offsetToDir)
			if err := pe.readOffset(&dataDir.Data, resourceHeader+offsetToDir); err != nil {
				return err
			}
			rValue := map[string]interface{}{}
			rValue["Rva"] = fmt.Sprintf("%016X", dataDir.Data.VirtualAddress)
			rValue["Size"] = fmt.Sprintf("%016X", dataDir.Data.Size)
			retMap[name] = rValue

			//fmt.Printf("vaddr %x, size %x\n", dataDir.Data.VirtualAddress, dataDir.Data.Size)
		}

		fileOffset += dirEntry.Size
		entryNum--
	}
	return nil
}
func (pe *PEFile) parseResources(resourceHeader, fileOffset uint32, retMap map[string]interface{}, bFirst bool) error {
	resourcesDesc := newResourceDirectory(fileOffset)
	if err := pe.readOffset(&resourcesDesc.Data, fileOffset); err != nil {
		return err
	}
	fileOffset += resourcesDesc.Size
	entryNum := resourcesDesc.Data.NumberOfIDEntries + resourcesDesc.Data.NumberOfNamedEntries
	for entryNum > 0 {
		dirEntry := newResourceDirectoryEntry(fileOffset)
		if err := pe.readOffset(&dirEntry.Data, fileOffset); err != nil {
			return err
		}
		//解析名称
		isNameString := ((uint64(dirEntry.Data.Name) & 0xffffffff) >> 0x1f) > 0
		nameOffset := uint32((uint64(dirEntry.Data.Name) & 0x7fffffff) >> 0x0)
		var name string
		if isNameString {
			//字符串名称
			startPos := resourceHeader + nameOffset
			lenbuff := bytes.NewBuffer(pe.data[startPos : startPos+2])
			var strLen uint16
			binary.Read(lenbuff, binary.LittleEndian, &strLen)
			buff := pe.data[startPos+2 : startPos+2+uint32(strLen*2)]
			var ascii []byte
			for i, v := range buff {
				if i%2 == 0 {
					ascii = append(ascii, v)
				}
			}
			name = string(ascii)
			//fmt.Println(string(ascii))
		} else {
			//序号名称
			name = fmt.Sprint(nameOffset)
			//第一层
			if bFirst {
				switch nameOffset {
				case 1:
					name = "RT_CURSOR"
				case 2:
					name = "RT_BITMAP"
				case 3:
					name = "RT_ICON"
				case 4:
					name = "RT_MENU"
				case 5:
					name = "RT_DIALOG"
				case 6:
					name = "RT_STRING"
				case 7:
					name = "RT_FONTDIR"
				case 8:
					name = "RT_FONT"
				case 9:
					name = "RT_ACCELERATOR"
				case 10:
					name = "RT_RCDATA"
				case 11:
					name = "RT_MESSAGETABLE"
				case 12:
					name = "RT_GROUP_CURSOR"
				case 14:
					name = "RT_GROUP_ICON"
				case 16:
					name = "RT_VERSION"
				case 17:
					name = "RT_DLGINCLUDE"
				case 19:
					name = "RT_PLUGPLAY"
				case 20:
					name = "RT_VXD"
				case 21:
					name = "RT_ANICURSOR"
				case 22:
					name = "RT_ANIICON"
				case 23:
					name = "RT_HTML"
				case 24:
					name = "RT_MANIFEST"
				}
			}
		}
		//解析数据
		dataEntry := newResourceDataEntry(fileOffset)
		if err := pe.readOffset(&dataEntry.Data, fileOffset); err != nil {
			return err
		}
		isDir := ((uint64(dataEntry.Data.Size) & 0xffffffff) >> 0x1f) > 0
		offsetToDir := uint32((uint64(dataEntry.Data.Size) & 0x7fffffff) >> 0x0)
		if isDir {
			//表示是目录
			rValue := map[string]interface{}{}
			pe.parseResources(resourceHeader, resourceHeader+offsetToDir, rValue, false)
			retMap[name] = rValue
		} else {
			//表示是文件
			dataDir := newResourceDataDirectory(resourceHeader + offsetToDir)
			if err := pe.readOffset(&dataDir.Data, resourceHeader+offsetToDir); err != nil {
				return err
			}
			rValue := map[string]interface{}{}
			rValue["Rva"] = fmt.Sprintf("%08X", dataDir.Data.VirtualAddress)
			rValue["Size"] = fmt.Sprintf("%08X", dataDir.Data.Size)
			retMap[name] = rValue
		}

		fileOffset += dirEntry.Size
		entryNum--
	}
	return nil
}
