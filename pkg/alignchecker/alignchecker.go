// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alignchecker

import (
	"fmt"
	"reflect"

	"github.com/cilium/ebpf/btf"
)

// CheckStructAlignments checks whether size and offsets match of the given
// C and Go structs which are listed in the given toCheck map (C struct name =>
// Go struct []reflect.Type).
//
// C struct layout is extracted from the given ELF object file's BTF info.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(pathToObj string, toCheck map[string][]reflect.Type, checkOffsets bool) error {
	spec, err := btf.LoadSpec(pathToObj)
	if err != nil {
		return fmt.Errorf("cannot parse BTF debug info %s: %w", pathToObj, err)
	}

	structInfo, err := getStructInfosFromBTF(spec, toCheck)
	if err != nil {
		return fmt.Errorf("cannot extract struct info from BTF %s: %w", pathToObj, err)
	}

	for cName, goStructs := range toCheck {
		if err := check(cName, goStructs, structInfo, checkOffsets); err != nil {
			return err
		}
	}
	return nil
}

type structInfo struct {
	size         uint32
	fieldOffsets map[string]uint32
}

func getStructInfosFromBTF(types *btf.Spec, toCheck map[string][]reflect.Type) (map[string]*structInfo, error) {
	structs := make(map[string]*structInfo)
	for name := range toCheck {
		t, err := types.AnyTypeByName(name)
		if err != nil {
			return nil, fmt.Errorf("looking up type %s by name: %w", name, err)
		}

		si, err := getStructInfoFromBTF(t)
		if err != nil {
			return nil, err
		}

		structs[name] = si
	}

	return structs, nil
}

func getStructInfoFromBTF(t btf.Type) (*structInfo, error) {
	switch typ := t.(type) {
	case *btf.Typedef:
		// Resolve Typedefs to their target types.
		return getStructInfoFromBTF(typ.Type)

	case *btf.Int:
		return &structInfo{
			size:         typ.Size,
			fieldOffsets: nil,
		}, nil

	case *btf.Struct:
		return &structInfo{
			size:         typ.Size,
			fieldOffsets: memberOffsets(typ.Members),
		}, nil

	case *btf.Union:
		return &structInfo{
			size:         typ.Size,
			fieldOffsets: memberOffsets(typ.Members),
		}, nil
	}

	return nil, fmt.Errorf("unsupported type: %s", t)
}

func memberOffsets(members []btf.Member) map[string]uint32 {
	unions := 0
	offsets := make(map[string]uint32, len(members))
	for _, member := range members {
		n := member.Name
		// Create surrogate names ($union0, $union1, etc) for unnamed union members.
		if n == "" {
			if _, ok := member.Type.(*btf.Union); ok {
				n = fmt.Sprintf("$union%d", unions)
				unions++
			}
		}
		offsets[n] = uint32(member.Offset.Bytes())
	}

	return offsets
}

func check(name string, toCheck []reflect.Type, structs map[string]*structInfo, checkOffsets bool) error {
	for _, g := range toCheck {
		c, found := structs[name]
		if !found {
			return fmt.Errorf("could not find C struct %s", name)
		}

		if c.size != uint32(g.Size()) {
			return fmt.Errorf("%s(%d) size does not match %s(%d)", g, g.Size(),
				name, c.size)
		}

		if !checkOffsets {
			continue
		}

		for i := 0; i < g.NumField(); i++ {
			fieldName := g.Field(i).Tag.Get("align")
			// Ignore fields without `align` struct tag
			if fieldName == "" {
				continue
			}
			goOffset := uint32(g.Field(i).Offset)
			cOffset := c.fieldOffsets[fieldName]
			if goOffset != cOffset {
				return fmt.Errorf("%s.%s offset(%d) does not match %s.%s(%d)",
					g, g.Field(i).Name, goOffset, name, fieldName, cOffset)
			}
		}
	}

	return nil
}
