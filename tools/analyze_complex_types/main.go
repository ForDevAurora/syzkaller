// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// analyze_complex_types discovers syscalls that share complex types.
//
// Usage:
//   analyze_complex_types -os=linux -arch=amd64 -calls=sendmsg$inet,sendmsg$unix -output-format=text
//
// The tool performs iterative propagation analysis to find all syscalls that directly or
// indirectly share complex types (structs, unions, flags, pointers, arrays) with the seed syscalls.

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// config holds command-line configuration.
type config struct {
	targetOS     string
	targetArch   string
	callNames    []string
	outputFormat string
}

// resolvedCall wraps a syscall with information about how it was resolved.
type resolvedCall struct {
	call           *prog.Syscall
	prefixExpanded bool // true if resolved via prefix matching
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze_complex_types: %v\n", err)
		fmt.Fprintf(os.Stderr, "Use -help for usage information\n")
		os.Exit(2)
	}
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "analyze_complex_types: %v\n", err)
		os.Exit(1)
	}
}

// parseFlags parses and validates command-line flags.
func parseFlags() (*config, error) {
	cfg := &config{}

	// Set defaults based on current platform
	targetOS := flag.String("os", runtime.GOOS, "target operating system")
	targetArch := flag.String("arch", runtime.GOARCH, "target architecture")
	callList := flag.String("calls", "", "comma-separated list of seed syscall names (supports prefix matching: 'sendmsg' matches all sendmsg$* variants)")
	outputFormat := flag.String("output-format", "text", "output format: text or json")
	flag.Parse()

	if *callList == "" {
		return nil, errors.New("must provide at least one syscall via -calls")
	}
	calls := splitAndClean(*callList)
	if len(calls) == 0 {
		return nil, errors.New("no valid syscall names provided via -calls")
	}

	format := strings.ToLower(*outputFormat)
	if format != "text" && format != "json" {
		return nil, fmt.Errorf("unsupported output format %q (must be 'text' or 'json')", *outputFormat)
	}

	cfg.targetOS = *targetOS
	cfg.targetArch = *targetArch
	cfg.callNames = calls
	cfg.outputFormat = format
	return cfg, nil
}

// splitAndClean splits a comma-separated string and trims whitespace.
func splitAndClean(value string) []string {
	parts := strings.Split(value, ",")
	var result []string
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name != "" {
			result = append(result, name)
		}
	}
	return result
}

// run executes the main analysis workflow.
func run(cfg *config) error {
	// Load the target
	target, err := prog.GetTarget(cfg.targetOS, cfg.targetArch)
	if err != nil {
		return fmt.Errorf("failed to load target %s/%s: %w", cfg.targetOS, cfg.targetArch, err)
	}

	// Resolve seed syscalls
	seeds, err := resolveCalls(target, cfg.callNames)
	if err != nil {
		return err
	}

	// Build type index for efficient lookup
	index, err := buildTypeIndex(target)
	if err != nil {
		return fmt.Errorf("failed to build type index: %w", err)
	}

	// Perform propagation analysis
	result, err := propagateComplexTypes(index, seeds)
	if err != nil {
		return err
	}

	// Render output in requested format
	switch cfg.outputFormat {
	case "text":
		return renderText(os.Stdout, result)
	case "json":
		return renderJSON(os.Stdout, result)
	default:
		return fmt.Errorf("unsupported output format %q", cfg.outputFormat)
	}
}

// resolveCalls converts syscall names to resolvedCall objects.
// Supports both exact matching and prefix matching:
// - Exact match: "sendmsg$inet" matches only that syscall
// - Prefix match: "sendmsg" matches "sendmsg", "sendmsg$inet", "sendmsg$unix", etc.
// Prefix matching only applies when the name contains no '$' and exact match fails.
// Returns resolved calls with information about whether they were prefix-expanded.
func resolveCalls(target *prog.Target, names []string) ([]resolvedCall, error) {
	seen := make(map[string]bool)
	var calls []resolvedCall
	var missing []string

	for _, name := range names {
		if seen[name] {
			continue
		}

		// If name contains '$', it's a specific specialization - try exact match only
		if strings.Contains(name, "$") {
			if call := target.SyscallMap[name]; call != nil {
				calls = append(calls, resolvedCall{
					call:           call,
					prefixExpanded: false,
				})
				seen[name] = true
			} else {
				missing = append(missing, name)
			}
			continue
		}

		// For names without '$', perform prefix matching to find all variants
		// This includes the base name itself (if it exists) plus all specializations
		prefix := name + "$"
		var matched []*prog.Syscall
		for _, call := range target.Syscalls {
			if call.Name == name || strings.HasPrefix(call.Name, prefix) {
				matched = append(matched, call)
			}
		}

		if len(matched) == 0 {
			missing = append(missing, name)
			continue
		}

		// Add all matched syscalls (all marked as prefix-expanded)
		for _, call := range matched {
			if !seen[call.Name] {
				calls = append(calls, resolvedCall{
					call:           call,
					prefixExpanded: true,
				})
				seen[call.Name] = true
			}
		}
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("unknown syscall(s) for target %s/%s: %v",
			target.OS, target.Arch, missing)
	}

	if len(calls) == 0 {
		return nil, errors.New("no valid syscalls resolved from -calls")
	}

	return calls, nil
}
