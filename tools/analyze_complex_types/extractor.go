// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"unsafe"

	"github.com/google/syzkaller/prog"
)

// typeIndex holds precomputed mappings between syscalls and complex types.
type typeIndex struct {
	// callTypes maps each syscall to its set of complex types
	callTypes map[*prog.Syscall]map[typeKey]typeInfo
	// typeToCalls is a reverse index: type -> syscalls using that type
	typeToCalls map[typeKey]*typeUsage
}

// typeUsage tracks which syscalls use a particular type.
type typeUsage struct {
	Info  typeInfo
	Calls []*prog.Syscall
}

// typeInfo contains metadata about a complex type.
type typeInfo struct {
	Key       typeKey
	Kind      typeKind
	Name      string
	Template  string
	TypeLabel string
}

// typeKey uniquely identifies a type using its kind and descriptor pointer.
// This approach is more reliable than using string names, as it handles
// anonymous types and avoids false matches between unrelated types with the same name.
type typeKey struct {
	Kind typeKind
	// Ptr is the address of the type descriptor, uniquely identifying the type
	Ptr uintptr
}

// typeKind represents the category of complex type.
type typeKind int

const (
	typeKindStruct typeKind = iota
	typeKindUnion
	typeKindFlags
	typeKindPtr
	typeKindArray
)

func (k typeKind) String() string {
	switch k {
	case typeKindStruct:
		return "struct"
	case typeKindUnion:
		return "union"
	case typeKindFlags:
		return "flags"
	case typeKindPtr:
		return "ptr"
	case typeKindArray:
		return "array"
	default:
		return fmt.Sprintf("unknown(%d)", k)
	}
}

// buildTypeIndex precomputes the type index for all syscalls in the target.
// This optimization avoids repeated type extraction during propagation.
func buildTypeIndex(target *prog.Target) (*typeIndex, error) {
	callTypes := make(map[*prog.Syscall]map[typeKey]typeInfo, len(target.Syscalls))
	typeToCalls := make(map[typeKey]*typeUsage)

	for _, call := range target.Syscalls {
		types := extractComplexTypes(call)
		callTypes[call] = types
		for key, info := range types {
			usage := typeToCalls[key]
			if usage == nil {
				usage = &typeUsage{Info: info}
				typeToCalls[key] = usage
			}
			usage.Calls = append(usage.Calls, call)
		}
	}
	return &typeIndex{
		callTypes:   callTypes,
		typeToCalls: typeToCalls,
	}, nil
}

// extractComplexTypes extracts all complex types used by a syscall.
// It leverages prog.ForeachCallType which automatically handles recursion and circular references.
func extractComplexTypes(call *prog.Syscall) map[typeKey]typeInfo {
	result := make(map[typeKey]typeInfo)
	prog.ForeachCallType(call, func(t prog.Type, ctx *prog.TypeCtx) {
		if info, ok := classifyType(t); ok {
			result[info.Key] = info
		}
	})
	return result
}

// classifyType determines if a type is a complex type and extracts its metadata.
// Returns (typeInfo, true) for complex types, (zero, false) for primitive types.
func classifyType(t prog.Type) (typeInfo, bool) {
	switch typ := t.(type) {
	case *prog.StructType:
		return makeTypeInfo(typeKindStruct, typ, typ.Name(), typ.TemplateName()), true
	case *prog.UnionType:
		return makeTypeInfo(typeKindUnion, typ, typ.Name(), typ.TemplateName()), true
	case *prog.FlagsType:
		return makeTypeInfo(typeKindFlags, typ, typ.Name(), typ.TemplateName()), true
	case *prog.PtrType:
		// Note: PtrType is included to track pointer types distinctly
		return makeTypeInfo(typeKindPtr, typ, typ.String(), typ.TemplateName()), true
	case *prog.ArrayType:
		// Note: ArrayType is included to track array types distinctly
		return makeTypeInfo(typeKindArray, typ, typ.String(), typ.TemplateName()), true
	default:
		// Exclude primitive types: IntType, ConstType, LenType, ProcType,
		// CsumType, VmaType, BufferType, ResourceType (handled separately)
		return typeInfo{}, false
	}
}

// makeTypeInfo constructs a typeInfo from a type object.
// Uses unsafe.Pointer to obtain a unique identifier for the type instance.
// The pointer parameter should be the concrete type pointer (e.g., *StructType).
func makeTypeInfo(kind typeKind, typePtr interface{}, name, template string) typeInfo {
	// Get the actual pointer address of the type instance.
	// For pointer types like *prog.StructType, unsafe.Pointer(typePtr) gives us
	// the address of the pointer variable itself. We need to dereference it.
	// However, since we're receiving an interface{}, we need to extract the data pointer.
	var ptr uintptr
	switch p := typePtr.(type) {
	case *prog.StructType:
		ptr = uintptr(unsafe.Pointer(p))
	case *prog.UnionType:
		ptr = uintptr(unsafe.Pointer(p))
	case *prog.FlagsType:
		ptr = uintptr(unsafe.Pointer(p))
	case *prog.PtrType:
		ptr = uintptr(unsafe.Pointer(p))
	case *prog.ArrayType:
		ptr = uintptr(unsafe.Pointer(p))
	default:
		// Fallback: use the address of the interface's data pointer
		ptr = uintptr(unsafe.Pointer(&typePtr))
	}

	return typeInfo{
		Key: typeKey{
			Kind: kind,
			Ptr:  ptr,
		},
		Kind:      kind,
		Name:      name,
		Template:  template,
		TypeLabel: kind.String(),
	}
}
