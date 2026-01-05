// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"sort"

	"github.com/google/syzkaller/prog"
)

// PropagationResult contains the results of the type propagation analysis.
type PropagationResult struct {
	Calls []*CallResult
	Types []typeInfo
}

// CallResult describes a discovered syscall and how it relates to the analysis.
type CallResult struct {
	Name             string
	Seed             bool       // true if this was a seed syscall
	PrefixExpanded   bool       // true if this seed was expanded from a prefix match
	MatchedTypes     []typeInfo // types that matched with already-discovered types
	AddedForResource bool       // true if this syscall was added for resource dependency
}

// ignoreResources lists resource types that should be ignored during dependency analysis.
// These are typically too generic or available through other means.
var ignoreResources = []string{
	"fd", "pid", "fd_dir", "uid", "gid", "time_sec", "time_nsec", "time_usec",
	"fd_io_uring", "timespec", "nfc_dev_id", "fd_cgroup", "fd_perf", "fd_nci",
	"fd_pidfd", "fd_rdma",
}

// propagateComplexTypes performs iterative BFS-style propagation to discover
// all syscalls that share complex types with the seed syscalls, followed by
// resource dependency analysis to ensure the result set is self-contained.
//
// Algorithm:
// Phase 1 - Type Propagation:
// 1. Start with seed syscalls and collect all their complex types
// 2. For each type, find all syscalls that use it
// 3. For each discovered syscall, collect its types and repeat
// 4. Continue until no new syscalls or types are discovered
//
// Phase 2 - Resource Dependency Analysis:
// 5. Analyze resource dependencies of all discovered syscalls
// 6. Add syscalls that produce needed resources or consume generated resources
// 7. Repeat until all resource dependencies are satisfied
func propagateComplexTypes(target *prog.Target, index *typeIndex, seeds []resolvedCall) (*PropagationResult, error) {
	if len(seeds) == 0 {
		return nil, errors.New("no seed syscalls provided")
	}

	seenCalls := make(map[*prog.Syscall]*CallResult)
	seenTypes := make(map[typeKey]typeInfo)
	var typeQueue []typeInfo

	// Initialize with seed syscalls
	for _, resolved := range seeds {
		call := resolved.call
		if call == nil {
			continue
		}
		if _, ok := seenCalls[call]; ok {
			continue
		}
		seenCalls[call] = &CallResult{
			Name:           call.Name,
			Seed:           true,
			PrefixExpanded: resolved.prefixExpanded,
		}

		// Add all types from seed syscalls to the queue
		for key, info := range index.callTypes[call] {
			if _, ok := seenTypes[key]; ok {
				continue
			}
			seenTypes[key] = info
			typeQueue = append(typeQueue, info)
		}
	}

	// BFS propagation: process each type and discover related syscalls
	for len(typeQueue) > 0 {
		info := typeQueue[0]
		typeQueue = typeQueue[1:]

		usage := index.typeToCalls[info.Key]
		if usage == nil {
			continue
		}

		// Find all syscalls that use this type
		for _, call := range usage.Calls {
			if _, processed := seenCalls[call]; processed {
				continue
			}

			// Check which types in this syscall match already-discovered types
			matched := collectMatches(index.callTypes[call], seenTypes)
			if len(matched) == 0 {
				continue
			}

			// Sort matched types for deterministic output
			sort.Slice(matched, func(i, j int) bool {
				if matched[i].Name == matched[j].Name {
					return matched[i].Kind < matched[j].Kind
				}
				return matched[i].Name < matched[j].Name
			})

			// Record this syscall as discovered
			seenCalls[call] = &CallResult{
				Name:         call.Name,
				MatchedTypes: matched,
			}

			// Add new types from this syscall to the queue
			for key, tinfo := range index.callTypes[call] {
				if _, ok := seenTypes[key]; ok {
					continue
				}
				seenTypes[key] = tinfo
				typeQueue = append(typeQueue, tinfo)
			}
		}
	}

	if len(seenCalls) == 0 {
		return nil, errors.New("analysis produced no syscalls (this should not happen)")
	}

	// Phase 2: Resource dependency analysis
	// Analyze and add syscalls needed to satisfy resource dependencies
	analyzeResourceDependencies(target, seenCalls)

	// Build result with deterministic ordering
	result := &PropagationResult{
		Calls: make([]*CallResult, 0, len(seenCalls)),
		Types: make([]typeInfo, 0, len(seenTypes)),
	}

	for _, call := range seenCalls {
		result.Calls = append(result.Calls, call)
	}
	for _, info := range seenTypes {
		result.Types = append(result.Types, info)
	}

	// Sort syscalls: by name, then seeds before derived, then by match count
	sort.Slice(result.Calls, func(i, j int) bool {
		if result.Calls[i].Name == result.Calls[j].Name {
			if result.Calls[i].Seed == result.Calls[j].Seed {
				return len(result.Calls[i].MatchedTypes) < len(result.Calls[j].MatchedTypes)
			}
			return result.Calls[j].Seed // seeds come first
		}
		return result.Calls[i].Name < result.Calls[j].Name
	})

	// Sort types: by name, then by kind
	sort.Slice(result.Types, func(i, j int) bool {
		if result.Types[i].Name == result.Types[j].Name {
			return result.Types[i].Kind < result.Types[j].Kind
		}
		return result.Types[i].Name < result.Types[j].Name
	})

	return result, nil
}

// collectMatches returns the types from callTypes that are present in seenTypes.
func collectMatches(callTypes map[typeKey]typeInfo, seenTypes map[typeKey]typeInfo) []typeInfo {
	var matches []typeInfo
	for key := range callTypes {
		if info, ok := seenTypes[key]; ok {
			matches = append(matches, info)
		}
	}
	return matches
}

// shouldIgnoreResource checks if a resource should be ignored during dependency analysis.
func shouldIgnoreResource(resName string) bool {
	for _, ignored := range ignoreResources {
		if resName == ignored {
			return true
		}
	}
	return false
}

// analyzeResourceDependencies performs iterative resource dependency analysis.
// Starting from the syscalls already discovered through type propagation, it finds
// all syscalls needed to satisfy resource dependencies, ensuring the result set is
// self-contained with respect to resource flow.
//
// Algorithm:
// 1. Collect all resources needed by current syscalls (InputResources)
// 2. Collect all resources generated by current syscalls (CreatesResources)
// 3. Find syscalls that can produce needed resources
// 4. Find syscalls that can consume generated resources
// 5. Add newly discovered syscalls and repeat until convergence
func analyzeResourceDependencies(target *prog.Target, seenCalls map[*prog.Syscall]*CallResult) {
	// Track resources we need and resources we can generate
	needResources := make(map[string]bool)
	generatedResources := make(map[string]bool)

	// Initialize with current syscalls
	for call := range seenCalls {
		for _, res := range call.InputResources() {
			if !shouldIgnoreResource(res.Name) {
				needResources[res.Name] = true
			}
		}
		for _, res := range call.CreatesResources() {
			if !shouldIgnoreResource(res.Name) {
				generatedResources[res.Name] = true
			}
		}
	}

	// Iterate until no new syscalls are discovered
	changed := true
	for changed {
		changed = false

		for _, call := range target.Syscalls {
			if _, alreadyIncluded := seenCalls[call]; alreadyIncluded {
				continue
			}

			shouldInclude := false

			// Check if this syscall produces any resources we need
			for _, res := range call.CreatesResources() {
				if shouldIgnoreResource(res.Name) {
					continue
				}
				if needResources[res.Name] {
					shouldInclude = true
					break
				}
			}

			// Check if this syscall consumes any resources we generate
			if !shouldInclude {
				for _, res := range call.InputResources() {
					if shouldIgnoreResource(res.Name) {
						continue
					}
					if generatedResources[res.Name] {
						shouldInclude = true
						break
					}
				}
			}

			if !shouldInclude {
				continue
			}

			// Add this syscall to the result set
			seenCalls[call] = &CallResult{
				Name:             call.Name,
				AddedForResource: true,
			}
			changed = true

			// Update our resource tracking
			for _, res := range call.InputResources() {
				if !shouldIgnoreResource(res.Name) && !needResources[res.Name] {
					needResources[res.Name] = true
				}
			}
			for _, res := range call.CreatesResources() {
				if !shouldIgnoreResource(res.Name) && !generatedResources[res.Name] {
					generatedResources[res.Name] = true
				}
			}
		}
	}
}
