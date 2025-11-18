// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Conservative resource-related analysis of programs.
// The analysis figures out what files descriptors are [potentially] opened
// at a particular point in program, what pages are [potentially] mapped,
// what files were already referenced in calls, etc.

package prog

import (
	"bytes"
	"fmt"
	"io"

	"github.com/google/syzkaller/pkg/image"
)

type state struct {
	target     *Target
	ct         *ChoiceTable
	corpus     []*Prog
	files      map[string]bool
	resources  map[string][]*ResultArg // 不能被ipv6_part1/mac_part1引用 TODOTODOTODO
	strings    map[string]bool
	ma         *memAlloc
	va         *vmaAlloc
	NetworkRes NetworkResources // Network resources used by the program.

}

type NetworkResources struct {
	// A map recording the correspondence between one object to another. Write this in go code
	// to avoid the need to serialize it.
	// For example, a map of file descriptors to sockets.
	Ipv6       map[*ResultArg]*ResultArg // ipv6 resources used by the program.
	Ipv6_part2 map[*ResultArg]*ResultArg // ipv6_part2 resources used by the program.
	Mac        map[*ResultArg]*ResultArg // mac resources used by the program.
	Mac_part2  map[*ResultArg]*ResultArg // mac_part2 resources used by the program.
}

func (s *state) InStructure(part1 *ResultArg, correlation_structure *map[*ResultArg]*ResultArg) (ipv6_part2 *ResultArg, ok bool) {
	if *correlation_structure == nil {
		return nil, false
	}
	part2, ok := (*correlation_structure)[part1]
	return part2, ok
}

func (s *state) FindRef(arg *ResultArg) *ResultArg {
	//fmt.Printf(">DEBUG: Finding reference for ResultArg %p\n", arg)
	if arg.Res == nil {
		//fmt.Printf(">DEBUG: ResultArg %p has no resource, returning itself.\n", arg)
		return arg
	} else {
		//fmt.Printf(">DEBUG: ResultArg %p has a resource %p, trying to find it.\n", arg, arg.Res)
		return s.FindRef(arg.Res)
	}
}

func (s *state) ChangeRef(arg, newArg Arg) {
	// Always make a ref and then replace it.
	// fmt.Printf(">> DEBUG: Changing the reference of ResultArg %p to point to bare-metal newArg %p.", arg, newArg)
	// new_arg_ref := MakeResultArg(newArg.Type(), newArg.Dir(), newArg, 0)
	// fmt.Printf(">> DEBUG: The new bare-metal reference is %p.\n", new_arg_ref)
	// replaceResultArg(arg, new_arg_ref)
	// fmt.Printf(">> DEBUG: With the new reference, ResultArg %p now points to %p with its resource value %p.\n", arg, new_arg_ref, arg.Res)

	// OPTION 1

	// if arg.Res == nil {
	// 	//fmt.Printf(">DEBUG: Changing reference of ResultArg, arg.Res is nil, DIRECTLY replacing with newArg. The original arg address is %p, trying to refer %p", arg, newArg)
	// 	// new_arg_ref := MakeResultArg(newArg.Type(), arg.Dir(), newArg, 0)
	// 	// //fmt.Printf(">DEBUG: now is %p.", new_arg_ref)
	// 	// replaceResultArg(arg, new_arg_ref) // 原本是裸的nil，现在替换成了一个带ref的arg。这是个很奇怪的事情！
	// 	replaceResultArg(arg, newArg) // 直接替换掉arg的引用，arg的资源值变成了newArg。
	// 	//fmt.Printf(">DEBUG: See! Now is %v, %p", arg, arg)
	// 	//arg = newArg
	// } else {
	// 	// if arg.Res.Res == nil {
	// 	// 	fmt.Println(">DEBUG: Changing reference of ResultArg, arg.Res is not nil, INDIRECTLY replacing with newArg.")
	// 	// 	//new_arg_ref := MakeResultArg(newArg.Type(), arg.Dir(), newArg, 0)
	// 	// 	//replaceResultArg(arg, new_arg_ref)
	// 	// 	s.ChangeRef(arg.Res, newArg)
	// 	// } else {
	// 	// 	panic("DEBUG: Found nested ResultArg, not considered yet.")
	// 	// }
	// 	// //fmt.Printf(">DEBUG: Changing reference of ResultArg, arg.Res is not nil, INDIRECTLY replacing with newArg. The original arg address is %p, trying to refer %p in %p", arg, newArg, arg.Res)
	// 	s.ChangeRef(arg.Res, newArg)
	// }

	// // OPTION 2
	// new_arg_ref := MakeResultArg(newArg.Type(), newArg.Dir(), newArg, 0)
	// replaceResultArg(arg, new_arg_ref)

	// OPTION 3, Lastest, change argument to a new one
	replaceArg(arg, newArg) // 直接替换掉arg的引用，arg的资源值变成了newArg。

}

func (s *state) Check_match(part1, part2 *ResultArg, g *Gen, correlation_structure *map[*ResultArg]*ResultArg, correlation_structure_part2 *map[*ResultArg]*ResultArg) (part1_changed, part2_changed *ResultArg) {
	//fmt.Printf(">DEBUG CHECK_MATCH: CHECK MATCHING PART1 AND PART2 with address %v, %v\n", part1, part2)
	if (*correlation_structure == nil) && (*correlation_structure_part2 == nil) {
		// fmt.Println(">DEBUG CHECK_MATCH: NETWORK RESOURCES NOT INITIALIZED. Initializing now")
		*correlation_structure = make(map[*ResultArg]*ResultArg)
		*correlation_structure_part2 = make(map[*ResultArg]*ResultArg)
	} else if (*correlation_structure == nil) || (*correlation_structure_part2 == nil) {
		panic(">DEBUG CHECK_MATCH: NETWORK RESOURCES NOT INITIALIZED. One of them is nil, this is not allowed.")
	}
	// nil is allowed. mismatch is not allowed.
	if part1 == nil || part2 == nil {
		//fmt.Printf(">DEBUG CHECK_MATCH: PART1 OR PART2 IS NIL. Irregular but allowed. with address %p, %p\n", part1, part2)
		return part1, part2
	}
	db_part2_id, ok := s.InStructure(part1, correlation_structure)
	if ok {
		// part1 is in the database, check part2
		if db_part2_id == part2 {
			//fmt.Printf(">DEBUG CHECK_MATCH: PART1 AND PART2 MATCH IN DB. With address %p, %p \n", part1, part2)
			part1_changed = part1
			part2_changed = part2
		} else {
			//fmt.Printf(">DEBUG CHECK_MATCH: PART1 MATCH IN DB, BUT PART2 NOT MATCH, REMATCH PART2. Originally, part1 is %p, part2 is %p. Now part1 is %p, part2 is %p \n", part1, part2, part1, db_part2_id)
			// part1 is in the database, but part2 is not, rematch part2
			//part2 = db_part2_id
			part1_changed = part1
			part2_changed = db_part2_id
		}
	} else {
		// part1 is not in the db, this is not possible. panic
		//fmt.Printf(">DEBUG CHECK_MATCH: PART1 NOT IN DB, VALIDATE PART2\n")
		if db_part1_id, ok := s.InStructure(part2, correlation_structure_part2); ok {
			// part2 is in the database, but part1 is not, rematch part1
			//fmt.Printf(">DEBUG CHECK_MATCH: PART2 MATCH IN DB, BUT PART1 NOT MATCH, REMATCH PART1. Originally, part1 is %p, part2 is %p. Now part1 is %p, part2 is %p \n", part1, part2, db_part1_id, part2)
			part1_changed = db_part1_id
			part2_changed = part2
		} else {
			//fmt.Printf(">DEBUG CHECK_MATCH: PART1 AND PART2 NOT MATCH IN DB, NO REMATCH POSSIBLE. \n")
			// both are not in the database, this is not possible. panic
			//fmt.Printf(">DEBUG CHECK_MATCH: Must be special value of both part1 and part2, not in the database. Ignore for now. The address is %p, %p\n", part1, part2)
			part1_changed = part1
			part2_changed = part2
			// g.GetState().InsertIPv6(part1_changed, part2_changed, &g.GetState().NetworkRes.Ipv6, &g.GetState().NetworkRes.Ipv6_part2)
		}
	}

	return part1_changed, part2_changed
}

// analyze analyzes the program p up to but not including call c.
func analyze(ct *ChoiceTable, corpus []*Prog, p *Prog, c *Call) *state {
	s := newState(p.Target, ct, corpus)
	resources := true
	for i, c1 := range p.Calls {
		if c1 == c {
			resources = false
		}
		// Shut up i's unused warning.
		_ = i
		s.analyzeImpl(c1, resources)
	}
	return s
}

func newState(target *Target, ct *ChoiceTable, corpus []*Prog) *state {
	s := &state{
		target:    target,
		ct:        ct,
		corpus:    corpus,
		files:     make(map[string]bool),
		resources: make(map[string][]*ResultArg),
		strings:   make(map[string]bool),
		ma:        newMemAlloc(target.NumPages * target.PageSize),
		va:        newVmaAlloc(target.NumPages),
	}
	return s
}

// analyze the resources generated by the syscall
func (s *state) analyze(c *Call) {
	s.analyzeImpl(c, true)
}

func (s *state) InsertStructure(part1 *ResultArg, part2 *ResultArg, correlation_structure *map[*ResultArg]*ResultArg, correlation_structure_part2 *map[*ResultArg]*ResultArg) {
	if *correlation_structure == nil {
		*correlation_structure = make(map[*ResultArg]*ResultArg)
		*correlation_structure_part2 = make(map[*ResultArg]*ResultArg)
	}
	// if _, ok := (*correlation_structure)[part1]; ok {
	// 	// If part1 is already in the correlation structure, we should not add it again.
	// 	panic(fmt.Sprintf("DEBUG: In InsertStructure process: part1 %v already exists in correlation structure, skipping\n", part1))
	// }
	// if _, ok := (*correlation_structure_part2)[part2]; ok {
	// 	// If part2 is already in the correlation structure, we should not add it again.
	// 	panic(fmt.Sprintf("DEBUG: In InsertStructure process: part2 %v already exists in correlation structure, skipping\n", part2))
	// }
	// if part1.Res != nil || part2.Res != nil {
	// 	panic(fmt.Sprintf("DEBUG: In InsertStructure process: part1 %v or part2 %v has a resource, this is not allowed", part1, part2))
	// }
	(*correlation_structure)[part1] = part2
	(*correlation_structure_part2)[part2] = part1
}

func (s *state) PickStructure(correlation_structure *map[*ResultArg]*ResultArg, correlation_structure_part2 *map[*ResultArg]*ResultArg) (*ResultArg, *ResultArg) {
	if *correlation_structure == nil || len(*correlation_structure) == 0 {
		return nil, nil
	}
	for part1, part2 := range *correlation_structure {
		if _, ok := (*correlation_structure_part2)[part2]; ok {
			return part1, part2
		}
	}
	return nil, nil
}

func (s *state) analyzeImpl(c *Call, resources bool) {
	hasAddr := false
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		switch a := arg.(type) {
		case *PointerArg:
			switch {
			case a.IsSpecial():
			case a.VmaSize != 0:
				s.va.noteAlloc(a.Address/s.target.PageSize, a.VmaSize/s.target.PageSize)
			case a.Res != nil:
				s.ma.noteAlloc(a.Address, a.Res.Size())
			}
		}
		switch typ := arg.Type().(type) {
		case *ResourceType:
			a := arg.(*ResultArg)
			if resources && a.Dir() != DirIn {
				s.resources[typ.Desc.Name] = append(s.resources[typ.Desc.Name], a) // 兼容resource
				if typ.Desc.Name == "ipv6_part1" || typ.Desc.Name == "ipv6_part2" || typ.Desc.Name == "mac_part1" || typ.Desc.Name == "mac_part2" {
					hasAddr = true
				}
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *BufferType:
			a := arg.(*DataArg)
			if a.Dir() != DirOut && len(a.Data()) != 0 &&
				(typ.Kind == BufferString || typ.Kind == BufferFilename) {
				val := string(a.Data())
				// Remove trailing zero padding.
				for len(val) >= 2 && val[len(val)-1] == 0 && val[len(val)-2] == 0 {
					val = val[:len(val)-1]
				}
				switch typ.Kind {
				case BufferString:
					s.strings[val] = true
				case BufferFilename:
					if len(val) < 3 || escapingFilename(val) {
						// This is not our file, probalby one of specialFiles.
						return
					}
					if val[len(val)-1] == 0 {
						val = val[:len(val)-1]
					}
					s.files[val] = true
				}
			}

		}
	})
	if hasAddr && resources {
		AnalyzeAddr(c, s) // Analyze the address generation syscalls.
	}
}

func AnalyzeAddr(c *Call, s *state) {
	// This is a syscall that generates IPv6 addresses. Here it could be called when mutating the prog, and therefore we need to supplement the network resource states.
	//Note that arg1 or arg2 could be nil. We should consider this case.

	var critical_structure *map[*ResultArg]*ResultArg
	var critical_structure_part2 *map[*ResultArg]*ResultArg

	if c.Meta.Name == "syz_ipv6_addr_gen" || c.Meta.Name == "syz_mac_addr_gen" {
		if c.Meta.Name == "syz_ipv6_addr_gen" {
			// fmt.Println("DEBUG: Analyzing syz_ipv6_addr_gen call")
			critical_structure = &s.NetworkRes.Ipv6
			critical_structure_part2 = &s.NetworkRes.Ipv6_part2
		} else {
			critical_structure = &s.NetworkRes.Mac
			critical_structure_part2 = &s.NetworkRes.Mac_part2
		}
		InsertWrapper(c.Args[1].(*PointerArg).Res.(*ResultArg), c.Args[2].(*PointerArg).Res.(*ResultArg), critical_structure, critical_structure_part2, s)

	} else {

		// First, get the ipv6/mac addresses from the call arguments.
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			switch a := arg.(type) {
			case *GroupArg:
				// Check if the group argument is StructType
				if _, ok := a.Type().(*StructType); ok {
					// Check if the name is ipv6_addr or mac_addr
					if a.Type().Name() == "ipv6_addr" {
						critical_structure = &s.NetworkRes.Ipv6
						critical_structure_part2 = &s.NetworkRes.Ipv6_part2
					} else if a.Type().Name() == "mac_addr" {
						critical_structure = &s.NetworkRes.Mac
						critical_structure_part2 = &s.NetworkRes.Mac_part2
					} else {
						return // Not the address generation call we are looking for.
					}
					InsertWrapper(a.Inner[0].(*ResultArg), a.Inner[1].(*ResultArg), critical_structure, critical_structure_part2, s)
				}
			}
		})
	}
}

func InsertWrapper(ipv6_arg1 *ResultArg, ipv6_arg2 *ResultArg, critical_structure *map[*ResultArg]*ResultArg, critical_structure_part2 *map[*ResultArg]*ResultArg, s *state) {

	// ipv6_part1 := s.FindRef(ipv6_arg1)
	// if ipv6_arg1 != ipv6_part1 {
	// 	if _, ok := s.InStructure(ipv6_part1, critical_structure); !ok {
	// 		panic("DEBUG: In analysis process: ipv6_arg1 is not equal to ipv6_part1, this should not happen. This is a bug in the analysis code.")
	// 	}
	// }
	// ipv6_part2 := s.FindRef(ipv6_arg2)
	// if ipv6_arg2 != ipv6_part2 {
	// 	if _, ok := s.InStructure(ipv6_part2, critical_structure_part2); !ok {
	// 		panic("DEBUG: In analysis process: ipv6_arg2 is not equal to ipv6_part2, this should not happen. This is a bug in the analysis code.")
	// 	}
	// }

	// if res, ok := s.InStructure(ipv6_part1, critical_structure); ok {
	// 	// fmt.Println("DEBUG: Mutating the call. Found existing IPv6 address in the correlation structure, ")
	// 	if res != ipv6_part2 {
	// 		panic(fmt.Sprintf("DEBUG: In analysis process: part1 %p already exists in correlation structure, but part2 %p is different", ipv6_part1, ipv6_part2))
	// 	} else {
	// 		// fmt.Println("DEBUG: In analysis process: part1 and part2 match in correlation structure, skipping insertion")
	// 		// panic(fmt.Sprintf("DEBUG: In analysis process: part1 and part2 match in correlation structure, skipping insertion. The address is %p, %p", c.Args[1].(*PointerArg), c.Args[2].(*PointerArg)))
	// 		fmt.Printf("DEBUG: In analysis process: part1 and part2 match in correlation structure, skipping insertion. The address is %p, %p", ipv6_part1, ipv6_part2)
	// 	}
	// } else if res, ok := s.InStructure(ipv6_part2, critical_structure_part2); ok {
	// 	// fmt.Println("DEBUG: Mutating the call. Found existing IPv6 address in the correlation structure, ")
	// 	if res != ipv6_part1 {
	// 		panic(fmt.Sprintf("DEBUG: In analysis process: part2 %p already exists in correlation structure, but part1 %p is different", ipv6_part2, ipv6_part1))
	// 	} else {
	// 		// fmt.Println("DEBUG: In analysis process: part2 and part1 match in correlation structure, skipping insertion")
	// 		// panic(fmt.Sprintf("DEBUG: In analysis process: part2 and part1 match in correlation structure, skipping insertion. The address is %p, %p", c.Args[1].(*PointerArg), c.Args[2].(*PointerArg)))
	// 		fmt.Printf("DEBUG: In analysis process: part2 and part1 match in correlation structure, skipping insertion. The address is %p, %p", ipv6_part1, ipv6_part2)
	// 	}
	// } else if ipv6_part1 == nil || ipv6_part2 == nil {
	// 	panic(fmt.Sprintf("DEBUG: In analysis, both parts are nil. This should not be possible, as nil pointer cannot be generated. The address is %p, %p", ipv6_part1, ipv6_part2)) // TODO!!!
	// 	////fmt.Printf(">DEBUG: In analysis process inside the analysis.go, part1 %p or part2 %p is nil. TODOTODOTODO!!!")
	// 	// ipv6_part1, ipv6_part2 = s.PickStructure(&s.NetworkRes.Ipv6, &s.NetworkRes.Ipv6_part2) // TODO!!!
	// } else {
	// Both of part1 and part2 is not nil, and they are not inside the structure. Insert them into the structure.
	ipv6_part1_ref := s.FindRef(ipv6_arg1)
	ipv6_part2_ref := s.FindRef(ipv6_arg2)
	//fmt.Printf(">DEBUG: In analysis process inside the analysis.go, part1 %p and part2 %p are not in the correlation structure, inserting them now.\n", ipv6_part1_ref, ipv6_part2_ref)
	s.InsertStructure(ipv6_part1_ref, ipv6_part2_ref, critical_structure, critical_structure_part2)
	// }
}

type parentStack []Arg

func allocStack() parentStack {
	// Let's save some allocations during stack traversal.
	return make([]Arg, 0, 4)
}

func pushStack(ps parentStack, a Arg) parentStack {
	return append(ps, a)
}

func popStack(ps parentStack) (parentStack, Arg) {
	if len(ps) > 0 {
		return ps[:len(ps)-1], ps[len(ps)-1]
	}
	return ps, nil
}

type ArgCtx struct {
	Parent      *[]Arg      // GroupArg.Inner (for structs) or Call.Args containing this arg.
	Fields      []Field     // Fields of the parent struct/syscall.
	Field       *Field      // Syscall field for this arg, nil if there it's not a field.
	Base        *PointerArg // Pointer to the base of the heap object containing this arg.
	Offset      uint64      // Offset of this arg from the base.
	Stop        bool        // If set by the callback, subargs of this arg are not visited.
	parentStack parentStack // Struct and union arguments by which the argument can be reached.
}

func ForeachSubArg(arg Arg, f func(Arg, *ArgCtx)) {
	foreachArgImpl(arg, nil, &ArgCtx{}, f)
}

func foreachSubArgWithStack(arg Arg, f func(Arg, *ArgCtx)) {
	foreachArgImpl(arg, nil, &ArgCtx{parentStack: allocStack()}, f)
}

func ForeachArg(c *Call, f func(Arg, *ArgCtx)) {
	ctx := &ArgCtx{}
	if c.Ret != nil {
		foreachArgImpl(c.Ret, nil, ctx, f)
	}
	ctx.Parent = &c.Args
	ctx.Fields = c.Meta.Args
	for i, arg := range c.Args {
		foreachArgImpl(arg, &ctx.Fields[i], ctx, f)
	}
}

func foreachArgImpl(arg Arg, field *Field, ctx *ArgCtx, f func(Arg, *ArgCtx)) {
	ctx0 := *ctx
	defer func() { *ctx = ctx0 }()

	if ctx.parentStack != nil {
		switch arg.Type().(type) {
		case *StructType, *UnionType:
			ctx.parentStack = pushStack(ctx.parentStack, arg)
		}
	}
	ctx.Field = field
	f(arg, ctx) // Never forget to go into this function! Here is where resources being added!
	if ctx.Stop {
		return
	}
	switch a := arg.(type) {
	case *GroupArg:
		overlayField := 0
		if typ, ok := a.Type().(*StructType); ok {
			ctx.Parent = &a.Inner
			ctx.Fields = typ.Fields
			overlayField = typ.OverlayField
		}
		var totalSize uint64
		for i, arg1 := range a.Inner {
			if i == overlayField {
				ctx.Offset = ctx0.Offset
			}
			foreachArgImpl(arg1, nil, ctx, f)
			size := arg1.Size()
			ctx.Offset += size
			if totalSize < ctx.Offset {
				totalSize = ctx.Offset - ctx0.Offset
			}
		}
		if debug {
			claimedSize := a.Size()
			varlen := a.Type().Varlen()
			if varlen && totalSize > claimedSize || !varlen && totalSize != claimedSize {
				panic(fmt.Sprintf("bad group arg size %v, should be <= %v for %#v type %#v",
					totalSize, claimedSize, a, a.Type().Name()))
			}
		}
	case *PointerArg:
		if a.Res != nil {
			ctx.Base = a
			ctx.Offset = 0
			foreachArgImpl(a.Res, nil, ctx, f)
		}
	case *UnionArg:
		foreachArgImpl(a.Option, nil, ctx, f)
	}
}

type RequiredFeatures struct {
	Bitmasks       bool
	Csums          bool
	FaultInjection bool
	Async          bool
}

func (p *Prog) RequiredFeatures() RequiredFeatures {
	features := RequiredFeatures{}
	for _, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			if a, ok := arg.(*ConstArg); ok {
				if a.Type().BitfieldOffset() != 0 || a.Type().BitfieldLength() != 0 {
					features.Bitmasks = true
				}
			}
			if _, ok := arg.Type().(*CsumType); ok {
				features.Csums = true
			}
		})
		if c.Props.FailNth > 0 {
			features.FaultInjection = true
		}
		if c.Props.Async {
			features.Async = true
		}
	}
	return features
}

type CallFlags int

const (
	CallExecuted CallFlags = 1 << iota // was started at all
	CallFinished                       // finished executing (rather than blocked forever)
	CallBlocked                        // finished but blocked during execution
)

type CallInfo struct {
	Flags  CallFlags
	Errno  int
	Signal []uint64
}

const (
	fallbackSignalErrno = iota
	fallbackSignalErrnoBlocked
	fallbackSignalCtor
	fallbackSignalFlags
	// This allows us to have 2M syscalls and leaves 8 bits for 256 errno values.
	// Linux currently have 133 errno's. Larger errno values will be truncated,
	// which is acceptable for fallback coverage.
	fallbackCallMask = 0x1fffff
)

func (p *Prog) FallbackSignal(info []CallInfo) {
	resources := make(map[*ResultArg]*Call)
	for i, c := range p.Calls {
		inf := &info[i]
		if inf.Flags&CallExecuted == 0 {
			continue
		}
		id := c.Meta.ID
		typ := fallbackSignalErrno
		if inf.Flags&CallFinished != 0 && inf.Flags&CallBlocked != 0 {
			typ = fallbackSignalErrnoBlocked
		}
		inf.Signal = append(inf.Signal, encodeFallbackSignal(typ, id, inf.Errno))
		if c.Meta.Attrs.BreaksReturns {
			break
		}
		if inf.Errno != 0 {
			continue
		}
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			if a, ok := arg.(*ResultArg); ok {
				resources[a] = c
			}
		})
		// Specifically look only at top-level arguments,
		// deeper arguments can produce too much false signal.
		flags := 0
		for _, arg := range c.Args {
			flags = extractArgSignal(arg, id, flags, inf, resources)
		}
		if flags != 0 {
			inf.Signal = append(inf.Signal,
				encodeFallbackSignal(fallbackSignalFlags, id, flags))
		}
	}
}

func extractArgSignal(arg Arg, callID, flags int, inf *CallInfo, resources map[*ResultArg]*Call) int {
	switch a := arg.(type) {
	case *ResultArg:
		flags <<= 1
		if a.Res != nil {
			ctor := resources[a.Res]
			if ctor != nil {
				inf.Signal = append(inf.Signal,
					encodeFallbackSignal(fallbackSignalCtor, callID, ctor.Meta.ID))
			}
		} else {
			if a.Val != a.Type().(*ResourceType).SpecialValues()[0] {
				flags |= 1
			}
		}
	case *ConstArg:
		const width = 3
		flags <<= width
		switch typ := a.Type().(type) {
		case *FlagsType:
			if typ.BitMask {
				for i, v := range typ.Vals {
					if a.Val&v != 0 {
						flags ^= 1 << (uint(i) % width)
					}
				}
			} else {
				for i, v := range typ.Vals {
					if a.Val == v {
						flags |= i % (1 << width)
						break
					}
				}
			}
		case *LenType:
			flags <<= 1
			if a.Val == 0 {
				flags |= 1
			}
		}
	case *PointerArg:
		flags <<= 1
		if a.IsSpecial() {
			flags |= 1
		}
	}
	return flags
}

func DecodeFallbackSignal(s uint64) (callID, errno int) {
	typ, id, aux := decodeFallbackSignal(s)
	switch typ {
	case fallbackSignalErrno, fallbackSignalErrnoBlocked:
		return id, aux
	case fallbackSignalCtor, fallbackSignalFlags:
		return id, 0
	default:
		panic(fmt.Sprintf("bad fallback signal type %v", typ))
	}
}

func encodeFallbackSignal(typ, id, aux int) uint64 {
	checkMaxCallID(id)
	if typ & ^7 != 0 {
		panic(fmt.Sprintf("bad fallback signal type %v", typ))
	}
	return uint64(typ) | uint64(id&fallbackCallMask)<<3 | uint64(aux)<<24
}

func decodeFallbackSignal(s uint64) (typ, id, aux int) {
	return int(s & 7), int((s >> 3) & fallbackCallMask), int(s >> 24)
}

func checkMaxCallID(id int) {
	if id & ^fallbackCallMask != 0 {
		panic(fmt.Sprintf("too many syscalls, have %v, max supported %v", id, fallbackCallMask+1))
	}
}

type AssetType int

const (
	MountInRepro AssetType = iota
)

func (p *Prog) ForEachAsset(cb func(name string, typ AssetType, r io.Reader, c *Call)) {
	for id, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			a, ok := arg.(*DataArg)
			if !ok || a.Type().(*BufferType).Kind != BufferCompressed {
				return
			}
			data, dtor := image.MustDecompress(a.Data())
			defer dtor()
			if len(data) == 0 {
				return
			}
			cb(fmt.Sprintf("mount_%v", id), MountInRepro, bytes.NewReader(data), c)
		})
	}
}

func (p *Prog) ContainsAny() bool {
	for _, c := range p.Calls {
		if p.Target.CallContainsAny(c) {
			return true
		}
	}
	return false
}
