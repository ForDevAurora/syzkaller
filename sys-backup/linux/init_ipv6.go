package linux

import (
	"github.com/google/syzkaller/prog"
)

func (arch *arch) generateIpv6Addr(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	typ := typ0.(*prog.StructType)
	var ipv6_part1_ref *prog.ResultArg
	var ipv6_part2_ref *prog.ResultArg
	var critical_structure *map[*prog.ResultArg]*prog.ResultArg
	var critical_structure_part2 *map[*prog.ResultArg]*prog.ResultArg
	if typ.TypeName == "ipv6_addr" {
		critical_structure = &g.GetState().NetworkRes.Ipv6
		critical_structure_part2 = &g.GetState().NetworkRes.Ipv6_part2
	} else {
		critical_structure = &g.GetState().NetworkRes.Mac
		critical_structure_part2 = &g.GetState().NetworkRes.Mac_part2
	}
	// For newly generated IPv6
	if old == nil {
		//fmt.Printf(">DEBUG : NEW STRUCT, GENERATE.\n")
		ipv6_part1_ref = g.GenerateArg(typ.Fields[0].Type, prog.DirIn, &calls).(*prog.ResultArg)
		ipv6_part2_ref = g.GenerateArg(typ.Fields[1].Type, prog.DirIn, &calls).(*prog.ResultArg)
		ipv6_part1 := g.FindRef(ipv6_part1_ref)
		ipv6_part2 := g.FindRef(ipv6_part2_ref)
		ipv6_part1_changed, ipv6_part2_changed := g.GetState().Check_match(ipv6_part1, ipv6_part2, g, critical_structure, critical_structure_part2)
		//g.ChangeRef(ipv6_part1_ref, ipv6_part1)
		if ipv6_part1_changed != ipv6_part1 {
			//fmt.Printf(">DEBUG IPV6: CHANGED IPV6 PART1 FROM %p TO %p\n", ipv6_part1, ipv6_part1_changed)
			g.ChangeRef(ipv6_part1_ref, ipv6_part1_changed)
		}
		if ipv6_part2_changed != ipv6_part2 {
			//fmt.Printf(">DEBUG IPV6: CHANGED IPV6 PART2 FROM %p TO %p\n", ipv6_part2, ipv6_part2_changed)
			g.ChangeRef(ipv6_part2_ref, ipv6_part2_changed)
		}
	} else {
		ipv6_part1_ref = old.(*prog.GroupArg).Inner[0].(*prog.ResultArg)
		ipv6_part2_ref = old.(*prog.GroupArg).Inner[1].(*prog.ResultArg)
		//fmt.Printf(">DEBUG IPV6: OLD IPV6 STRUCT, PICK ANOTHER ADDRESS.\n")
		new_ipv6_part1, new_ipv6_part2 := g.GetState().PickStructure(critical_structure, critical_structure_part2)
		if new_ipv6_part1 != nil && new_ipv6_part2 != nil {
			//fmt.Printf(">DEBUG IPV6: OLD IPV6 STRUCT, CHANGED TO NEW ADDRESS. Original Address: %p with new part %p\n", ipv6_part1_ref, new_ipv6_part1)
			g.ChangeRef(ipv6_part1_ref, new_ipv6_part1)
			//fmt.Printf(">DEBUG IPV6: CHANGED. Now Address: %p with new part %p\n", ipv6_part1_ref, new_ipv6_part1)
			g.ChangeRef(ipv6_part2_ref, new_ipv6_part2)
			//fmt.Printf(">DEBUG IPV6: OLD IPV6 STRUCT, CHANGED TO NEW ADDRESS.\n")
		} else {
			//fmt.Printf(">DEBUG IPV6: OLD IPV6 STRUCT, BUT NO EXISTING CORRELATIONS FOUND. KEEP IT THE ORIGINAL WAY.\n")
		}
		//fmt.Printf(">DEBUG IPV6: OLD IPV6 STRUCT, PICK ANOTHER ADDRESS.\n")
	}

	arg = prog.MakeGroupArg(typ, dir, []prog.Arg{ipv6_part1_ref, ipv6_part2_ref})

	return
}
