// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS      = flag.String("os", runtime.GOOS, "target OS")
	flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
	flagVersion = flag.Uint64("version", 0, "database version")
	flagExact   = flag.Bool("exact", false, "exact match syscall name (default: substring match)")
)

func main() {
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) < 3 {
		usage()
	}

	srcDB := args[0]
	dstDB := args[1]
	syscalls := args[2:]

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		tool.Failf("failed to find target: %v", err)
	}

	filter(srcDB, dstDB, syscalls, target, *flagVersion, *flagExact)
}

func usage() {
	fmt.Fprintf(os.Stderr, `syz-db-filter filters corpus.db by syscall names.

Usage:
  syz-db-filter [flags] <src-corpus.db> <dst-corpus.db> <syscall1> [syscall2 ...]

Arguments:
  src-corpus.db    Source corpus database file
  dst-corpus.db    Destination corpus database file (will be created/overwritten)
  syscall1 ...     One or more syscall names to filter by

Flags:
  -os string       Target OS (default: %s)
  -arch string     Target arch (default: %s)
  -version uint    Database version for output file
  -exact           Exact match syscall name (default: substring match)

Examples:
  Filter programs containing sendmsg:
    syz-db-filter corpus.db filtered.db sendmsg

  Filter programs containing any of multiple syscalls:
    syz-db-filter corpus.db filtered.db sendmsg recvmsg socket

  Filter with exact match:
    syz-db-filter -exact corpus.db filtered.db sendmsg$inet

`, runtime.GOOS, runtime.GOARCH)
	os.Exit(1)
}

func filter(srcFile, dstFile string, syscalls []string, target *prog.Target, version uint64, exact bool) {
	srcDB, err := db.Open(srcFile, false)
	if err != nil {
		tool.Failf("failed to open source database: %v", err)
	}

	fmt.Printf("Source corpus: %d programs\n", len(srcDB.Records))
	fmt.Printf("Filtering by syscalls (exact=%v):\n", exact)
	for _, s := range syscalls {
		fmt.Printf("  - %q\n", s)
	}

	var records []db.Record
	matchCount := 0

	for _, rec := range srcDB.Records {
		callSet, _, err := prog.CallSet(rec.Val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse call set: %v\n", err)
			continue
		}

		if matchesSyscalls(callSet, syscalls, exact) {
			records = append(records, db.Record{
				Val: rec.Val,
				Seq: rec.Seq,
			})
			matchCount++
		}
	}

	if len(records) == 0 {
		fmt.Println("No matching programs found.")
		return
	}

	if err := db.Create(dstFile, version, records); err != nil {
		tool.Failf("failed to create destination database: %v", err)
	}

	fmt.Printf("Filtered corpus: %d programs (%.1f%%)\n", matchCount, float64(matchCount)*100/float64(len(srcDB.Records)))
	fmt.Printf("Output written to: %s\n", dstFile)
}

func matchesSyscalls(callSet map[string]struct{}, syscalls []string, exact bool) bool {
	for call := range callSet {
		for _, target := range syscalls {
			if exact {
				if call == target {
					return true
				}
			} else {
				if strings.Contains(call, target) {
					return true
				}
			}
		}
	}
	return false
}
