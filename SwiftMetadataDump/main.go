/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/blacktop/go-macho"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <executable> <option> <architecture>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options: types, protocols, fields, associated_types\n")
		fmt.Fprintf(os.Stderr, "Architecture: Amd64, AARCH64, etc.\n")
		return
	}

	validOptions := map[string]bool{
		"types":            true,
		"protocols":        true,
		"fields":           true,
		"associated_types": true,
	}
	if !validOptions[os.Args[2]] {
		fmt.Fprintf(os.Stderr, "Error: Invalid option '%s'. Valid options are: types, protocols, fields, associated_types\n", os.Args[2])
		return
	}

	var m *macho.File

	if fat, err := macho.OpenFat(os.Args[1]); err == nil {
		defer fat.Close()
		arch := os.Args[3]
		found := false
		for _, archFile := range fat.Arches {
			if archFile.CPU.String() == arch {
				m = archFile.File
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Error: Architecture '%s' not found in the fat binary\n", arch)
			return
		}
	} else {
		var err error
		m, err = macho.Open(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open file (%s)\n", err)
			return
		}
	}
	defer m.Close()

	if !m.HasSwift() {
		fmt.Fprintf(os.Stderr, "%s is not written in Swift\n", os.Args[1])
		return
	}

	switch os.Args[2] {
	case "types":
		types, err := m.GetSwiftTypes()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to retrieve Swift type information (%s)", err)
			return
		}
		bytes, err := json.Marshal(types)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to convert to JSON (%s)", err)
			return
		}
		fmt.Println(string(bytes))

	case "protocols":
		protsconfs, err := m.GetSwiftProtocolConformances()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to retrieve Swift protocol conformance information (%s)", err)
			return
		}
		bytes, err := json.Marshal(protsconfs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to convert to JSON (%s)", err)
			return
		}
		fmt.Println(string(bytes))

	case "fields":
		fields, err := m.GetSwiftFields()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to retrieve Swift field information (%s)", err)
			return
		}
		bytes, err := json.Marshal(fields)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to convert to JSON (%s)", err)
			return
		}
		fmt.Println(string(bytes))

	case "associated_types":
		associated_types, err := m.GetSwiftAssociatedTypes()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to retrieve Swift associated type information (%s)", err)
			return
		}
		bytes, err := json.Marshal(associated_types)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to convert to JSON (%s)", err)
			return
		}
		fmt.Println(string(bytes))

	default:
		fmt.Println("Unknown option")
	}
}
