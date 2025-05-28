package main

import (
	"fmt"
	"slices"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// 数组以记录ignore resources
var ignoreResources = []string{
	"fd", "pid", "fd_dir", "uid", "gid", "time_sec", "time_nsec", "time_usec", "fd_io_uring", "timespec"}

// findConsumers returns all syscalls that, transitively, take
// any of the resource kinds in initialRes as input.
func findConsumers(target *prog.Target, initialRes []string) []*prog.Syscall {
	// visitedRes tracks which resource kinds we've already seen.
	visitedRes := make(map[string]bool)
	for _, r := range initialRes {
		visitedRes[r] = true
	}

	// callSet tracks which syscalls we've already marked as consumers.
	callSet := make(map[*prog.Syscall]bool)

	changed := true
	for changed {
		changed = false
		// walk over every syscall in the target
		for _, call := range target.Syscalls {
			if callSet[call] {
				continue
			}
			// Does this call consume any known resource?
			consumes := false
			for _, f := range call.Args {
				// resource‐typed args are *ResourceType
				rt, ok := f.Type.(*prog.ResourceType)
				if !ok {
					continue
				}
				// f.Dir(DirIn) tells you whether it's an input (or inout)
				if dir := f.Dir(prog.DirIn); (dir == prog.DirIn || dir == prog.DirInOut) &&
					visitedRes[rt.Desc.Name] {
					consumes = true
					break
				}
			}
			if !consumes {
				continue
			}
			// mark this call
			callSet[call] = true
			// now any resources it *produces* get added to visitedRes
			for _, f := range call.Args {
				rt, ok := f.Type.(*prog.ResourceType)
				if !ok {
					continue
				}
				if dir := f.Dir(prog.DirOut); dir == prog.DirOut || dir == prog.DirInOut {
					name := rt.Desc.Name
					if !visitedRes[name] {
						visitedRes[name] = true
						changed = true
					}
				}
			}
		}
	}

	// collect the results
	var res []*prog.Syscall
	for c := range callSet {
		res = append(res, c)
	}
	return res
}

// findResourceDependencies 查找给定系统调用集合生成的所有资源，以及使用这些资源的系统调用
func findResourceDependencies(target *prog.Target, initialCalls []*prog.Syscall) []*prog.Syscall {
	// 跟踪已经处理过的系统调用
	processedCalls := make(map[*prog.Syscall]bool)
	// 跟踪已经发现的资源
	discoveredResources := make(map[string]bool)

	fmt.Println("\n=== 初始系统调用 ===")
	// 初始化已处理的系统调用集合
	for _, call := range initialCalls {
		processedCalls[call] = true
		fmt.Printf("系统调用: %s\n", call.Name)
		// 记录这个系统调用生成的所有资源
		for _, res := range call.CreatesResources() {
			discoveredResources[res.Name] = true
			fmt.Printf("  生成资源: %s\n", res.Name)
		}
	}

	round := 1
	changed := true
	for changed {
		changed = false
		fmt.Printf("\n=== 第 %d 轮分析 ===\n", round)
		fmt.Printf("当前已处理系统调用: %d\n", len(processedCalls))
		round++

		// 遍历所有系统调用
		for _, call := range target.Syscalls {
			if processedCalls[call] {
				continue
			}

			// 检查这个系统调用是否使用了任何已发现的资源
			usesDiscoveredResource := false
			for _, res := range call.UsesResources() {
				if discoveredResources[res.Name] {
					usesDiscoveredResource = true
					fmt.Printf(" Syscall %s 使用资源: %s\n", call.Name, res.Name)
					break
				}
			}

			for _, res := range call.CreatesResources() {
				if discoveredResources[res.Name] {
					usesDiscoveredResource = true
					fmt.Printf(" Syscall %s 生成资源: %s\n", call.Name, res.Name)
					break
				}
			}

			if !usesDiscoveredResource {
				continue
			}

			// 将这个系统调用添加到已处理集合
			processedCalls[call] = true
			changed = true
			fmt.Printf("发现新系统调用: %s\n", call.Name)

			// 记录这个系统调用生成的所有新资源
			for _, res := range call.CreatesResources() {
				if !discoveredResources[res.Name] {
					discoveredResources[res.Name] = true
					changed = true
					fmt.Printf("  生成新资源: %s\n", res.Name)
				}
			}
			// 记录这个系统使用的所有新资源
			for _, res := range call.UsesResources() {
				if !discoveredResources[res.Name] {
					discoveredResources[res.Name] = true
					changed = true
					fmt.Printf("  使用新资源: %s\n", res.Name)
				}
			}
		}
	}

	// 收集结果
	var result []*prog.Syscall
	for call := range processedCalls {
		result = append(result, call)
	}
	return result
}

func findResourceDependenciesPermissive(target *prog.Target, initialCalls []*prog.Syscall) []*prog.Syscall {
	// 跟踪已经处理过的系统调用
	processedCalls := make(map[*prog.Syscall]bool)
	// 跟踪已经发现的资源
	needResources := make(map[string]bool)
	generatedResources := make(map[string]bool)

	fmt.Println("\n=== 初始系统调用 ===")
	// 初始化已处理的系统调用集合
	for _, call := range initialCalls {
		processedCalls[call] = true
		fmt.Printf("系统调用: %s\n", call.Name)
		// 记录这个系统调用需要或生成的所有资源
		for _, res := range call.InputResources() {
			needResources[res.Name] = true
			fmt.Printf("  需要资源: %s\n", res.Name)
		}
		for _, res := range call.CreatesResources() {
			generatedResources[res.Name] = true
			fmt.Printf("  生成资源: %s\n", res.Name)
		}
	}

	round := 1
	changed := true
	for changed {
		changed = false
		fmt.Printf("\n=== 第 %d 轮分析 ===\n", round)
		fmt.Printf("当前已处理系统调用: %d\n", len(processedCalls))
		round++

		// 遍历所有系统调用
		for _, call := range target.Syscalls {
			if processedCalls[call] {
				continue
			}

			usesDiscoveredResource := false
			for _, res := range call.CreatesResources() {
				if needResources[res.Name] && !slices.Contains(ignoreResources, res.Name) {
					usesDiscoveredResource = true
					fmt.Printf(" Syscall %s 生成资源: %s\n", call.Name, res.Name)
					break
				}
			}

			for _, res := range call.InputResources() {
				if generatedResources[res.Name] && !slices.Contains(ignoreResources, res.Name) {
					usesDiscoveredResource = true
					fmt.Printf(" Syscall %s 使用资源: %s\n", call.Name, res.Name)
					break
				}
			}

			if !usesDiscoveredResource {
				continue
			}

			// 将这个系统调用添加到已处理集合
			processedCalls[call] = true
			changed = true
			fmt.Printf("发现新系统调用: %s\n", call.Name)

			// 记录这个系统使用的所有新资源
			for _, res := range call.InputResources() {
				if !needResources[res.Name] && !slices.Contains(ignoreResources, res.Name) {
					needResources[res.Name] = true
					fmt.Printf("  需要新资源: %s\n", res.Name)
				}
			}

			for _, res := range call.CreatesResources() {
				if !generatedResources[res.Name] && !slices.Contains(ignoreResources, res.Name) {
					generatedResources[res.Name] = true
					fmt.Printf("  生成新资源: %s\n", res.Name)
				}
			}
		}
	}

	// 收集结果
	var result []*prog.Syscall
	for call := range processedCalls {
		result = append(result, call)
	}
	return result
}

func main() {
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		panic(err)
	}

	// 示例：从一些初始系统调用开始
	initialCalls := []*prog.Syscall{
		target.SyscallMap["syz_port_gen"],
		target.SyscallMap["syz_ipv4_addr_gen"],
		target.SyscallMap["syz_ipv6_addr_gen"],
		target.SyscallMap["syz_mac_addr_gen"],
		target.SyscallMap["syz_extract_tcp_res"],
		target.SyscallMap["syz_extract_tcp_res$synack"],
		target.SyscallMap["syz_emit_ethernet"],
		target.SyscallMap["accept"],
		target.SyscallMap["accept$inet"],
		target.SyscallMap["accept$inet6"],
	}

	// 查找所有相关的系统调用
	relatedCalls := findResourceDependenciesPermissive(target, initialCalls)

	fmt.Println("== 相关系统调用 ==")
	// Print the result in ["a", "b"] with getting there name
	fmt.Printf("[")
	for _, call := range relatedCalls {
		fmt.Printf("\"%s\",", call.Name)
	}
	fmt.Printf("]\n")
}
