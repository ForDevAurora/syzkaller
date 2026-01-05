// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// renderText outputs the analysis result in human-readable text format.
func renderText(w io.Writer, result *PropagationResult) error {
	if result == nil {
		return errors.New("no analysis result to render")
	}

	fmt.Fprintf(w, "=== Complex Type Propagation Analysis ===\n")
	fmt.Fprintf(w, "Discovered %d syscalls sharing %d complex types\n\n", len(result.Calls), len(result.Types))

	// Group syscalls by category
	var directSeeds, expandedSeeds, derived, resourceAdded []*CallResult
	for _, call := range result.Calls {
		if call.Seed {
			if call.PrefixExpanded {
				expandedSeeds = append(expandedSeeds, call)
			} else {
				directSeeds = append(directSeeds, call)
			}
		} else if call.AddedForResource {
			resourceAdded = append(resourceAdded, call)
		} else {
			derived = append(derived, call)
		}
	}

	// Output direct seed syscalls
	if len(directSeeds) > 0 {
		fmt.Fprintf(w, "Direct seed syscalls (%d):\n", len(directSeeds))
		for _, call := range directSeeds {
			fmt.Fprintf(w, "  - %s\n", call.Name)
		}
		fmt.Fprintf(w, "\n")
	}

	// Output prefix-expanded seed syscalls
	if len(expandedSeeds) > 0 {
		fmt.Fprintf(w, "Prefix-expanded seed syscalls (%d):\n", len(expandedSeeds))
		for _, call := range expandedSeeds {
			fmt.Fprintf(w, "  - %s\n", call.Name)
		}
		fmt.Fprintf(w, "\n")
	}

	// Output derived syscalls with their matched types
	if len(derived) > 0 {
		fmt.Fprintf(w, "Derived syscalls (via type propagation) (%d):\n", len(derived))
		for _, call := range derived {
			fmt.Fprintf(w, "  - %s\n", call.Name)
			if len(call.MatchedTypes) > 0 {
				fmt.Fprintf(w, "    matched: %s\n", joinTypeNames(call.MatchedTypes))
			}
		}
		fmt.Fprintf(w, "\n")
	}

	// Output syscalls added for resource dependencies
	if len(resourceAdded) > 0 {
		fmt.Fprintf(w, "Resource dependency syscalls (%d):\n", len(resourceAdded))
		for _, call := range resourceAdded {
			fmt.Fprintf(w, "  - %s\n", call.Name)
		}
		fmt.Fprintf(w, "\n")
	}

	// Output all discovered complex types
	if len(result.Types) > 0 {
		fmt.Fprintf(w, "Complex types (%d):\n", len(result.Types))
		for _, info := range result.Types {
			template := ""
			if info.Template != "" && info.Template != info.Name {
				template = fmt.Sprintf(" (template=%s)", info.Template)
			}
			fmt.Fprintf(w, "  - [%s] %s%s\n", info.Kind.String(), info.Name, template)
		}
	}

	return nil
}

// renderJSON outputs the analysis result in JSON format.
func renderJSON(w io.Writer, result *PropagationResult) error {
	if result == nil {
		return errors.New("no analysis result to render")
	}

	payload := struct {
		SyscallCount int              `json:"syscall_count"`
		TypeCount    int              `json:"type_count"`
		Calls        []jsonCallResult `json:"calls"`
		Types        []jsonTypeInfo   `json:"types"`
	}{
		SyscallCount: len(result.Calls),
		TypeCount:    len(result.Types),
		Calls:        make([]jsonCallResult, 0, len(result.Calls)),
		Types:        make([]jsonTypeInfo, 0, len(result.Types)),
	}

	for _, call := range result.Calls {
		payload.Calls = append(payload.Calls, jsonCallResult{
			Name:             call.Name,
			Seed:             call.Seed,
			PrefixExpanded:   call.PrefixExpanded,
			AddedForResource: call.AddedForResource,
			MatchedTypes:     toJSONTypes(call.MatchedTypes),
		})
	}
	for _, info := range result.Types {
		payload.Types = append(payload.Types, jsonTypeInfo{
			Kind:     info.Kind.String(),
			Name:     info.Name,
			Template: info.Template,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

// jsonCallResult represents a syscall in JSON format.
type jsonCallResult struct {
	Name             string         `json:"name"`
	Seed             bool           `json:"seed"`
	PrefixExpanded   bool           `json:"prefix_expanded,omitempty"`
	AddedForResource bool           `json:"added_for_resource,omitempty"`
	MatchedTypes     []jsonTypeInfo `json:"matched_types,omitempty"`
}

// jsonTypeInfo represents a type in JSON format.
type jsonTypeInfo struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Template string `json:"template,omitempty"`
}

// toJSONTypes converts typeInfo slice to JSON representation.
func toJSONTypes(types []typeInfo) []jsonTypeInfo {
	result := make([]jsonTypeInfo, 0, len(types))
	for _, t := range types {
		result = append(result, jsonTypeInfo{
			Kind:     t.Kind.String(),
			Name:     t.Name,
			Template: t.Template,
		})
	}
	return result
}

// joinTypeNames formats a list of types as a readable string.
func joinTypeNames(types []typeInfo) string {
	names := make([]string, 0, len(types))
	for _, t := range types {
		names = append(names, fmt.Sprintf("%s(%s)", t.Name, t.Kind.String()))
	}
	return strings.Join(names, ", ")
}
