package main

import (
	"fmt"
	"github.com/l0g1n/pefile-go"
	"os"
)

func main() {
	fmt.Println("hello everyone, lets parse your PEFile")
	//args:= os.Args[1:]
	//if len(args) == 0 {
	//	fmt.Println("Must specify the filename of the PEFile")
	//	os.Exit(-1)
	//}
	//filename := args[0]
	//filename := "D:\\H\\mae2.0_module\\测试程序\\calc32.exe"
	//filename := "D:\\H\\mae2.0_module\\bugs\\actxprxy.dll"
	filename := "D:\\H\\mae2.0_module\\bugs\\zipfldr.dll"
	pefile, err := pefile.NewPEFile(filename)
	if err != nil {
		fmt.Println("Ooopss looks like there was a problem")
		fmt.Println(err)
		os.Exit(2)
	}

	//fmt.Println(pefile.Filename)

	for _, e := range pefile.Errors {
		fmt.Println("Parser warning:", e)
	}

	//fmt.Println(pefile.DosHeader.String())
	//fmt.Println(pefile.NTHeader.String())
	//fmt.Println(pefile.COFFFileHeader.String())
	//fmt.Println(pefile.OptionalHeader)

	//for key, val := range pefile.OptionalHeader.DataDirs {
	//	fmt.Println(key)
	//	fmt.Println(val)
	//}

	for _, s := range pefile.Sections {
		fmt.Println(s.String())
	}

	/*for _, val := range pefile.ImportDescriptors {
		fmt.Println(val)
		for _, val2 := range val.Imports {
			fmt.Println(val2)
		}
	}*/

	fmt.Println("\nDIRECTORY_ENTRY_IMPORT\n")
	if pefile.OptionalHeader64 != nil {
		//64位程序
		for _, entry := range pefile.ImportDescriptors {
			fmt.Println(string(entry.Dll))
			for _, imp := range entry.Imports64 {
				var funcname string
				if len(imp.Name) == 0 {
					funcname = fmt.Sprintf("ordinal+%d", imp.Ordinal)
				} else {
					funcname = string(imp.Name)
				}
				fmt.Println("\t", funcname)
				fmt.Printf("%x %x %x\n", imp.Hint, imp.ThunkRva, imp.ThunkOffset)
			}
		}
	} else {
		for _, entry := range pefile.ImportDescriptors {
			fmt.Println(string(entry.Dll))
			fmt.Println(entry.String())
			for _, imp := range entry.Imports {
				var funcname string
				if len(imp.Name) == 0 {
					funcname = fmt.Sprintf("ordinal+%d", imp.Ordinal)
				} else {
					funcname = string(imp.Name)
				}
				fmt.Println("\t", funcname)
				fmt.Printf("%x %x %x\n", imp.Hint, imp.ThunkRva, imp.ThunkOffset)
			}
		}
	}

	if pefile.ExportDirectory != nil {
		fmt.Println("\nDIRECTORY_ENTRY_EXPORT\n")
		fmt.Println(pefile.ExportDirectory)
		for _, entry := range pefile.ExportDirectory.Exports {
			fmt.Printf("%d: %s:0x%x, forward: %s", entry.Ordinal, string(entry.Name), entry.Address, entry.Forwarder)
			fmt.Println(entry.String())
		}
	}

}
