// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strings"
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

// excludedPrefixes lists type name prefixes that should be excluded from analysis.
// These types are too generic or subsystem-specific and create noise in the results.
// Organized by subsystem for maintainability.
var excludedPrefixes = []string{
	// USB / HID stack
	"usb_", "usbmon_", "vusb_", "xhci_", "uhci_", "ohci_",
	"hid_", "uhid_", "usbhid_",

	// Bluetooth / Wireless protocols
	"bluetooth_", "bt_", "bnep_", "rfcomm_", "l2cap_", "hci_", "mgmt_",
	"ieee80211_", "nl80211_", "cfg80211_",
	"zigbee_", "ieee802154_", "mac802154_",

	// File systems (generic VFS + specific implementations)
	"fs_", "fscrypt", "file_", "inode_", "dentry_", "dir_", "fuse_",
	"ext4_", "ext2_", "xfs_", "btrfs_", "f2fs_", "gfs_", "ceph_",
	"nfs_", "cifs_", "overlayfs_", "tmpfs_", "ubifs_",

	// Virtualization / Hypervisors
	"kvm_", "vhost_", "virtio_", "vmbus_", "xen_", "hyperv_", "ghcb_",
	"sev_", "tdx_", "snp_",

	// Graphics / DRM / Display
	"drm_", "vgem_", "vmwgfx_", "nouveau_", "amdgpu_", "i915_", "virtgpu_", "udmabuf_",

	// // Networking devices / protocols
	// "netdev_", "ethtool_", "ifreq", "tc_", "tap_", "tun_", "pktgen_",
	// "can_", "nl_", "rtnl_", "route_", "bridge_", "bonding_", "team_",
	// "ieee802154_", "macsec_", "wireguard_", "ipvlan_", "macvlan_", "xdp_",

	// eBPF / tracing / perf
	"bpf_", "btf_", "perf_", "trace_", "ftrace_", "uprobes_", "kprobes_", "ktrace_",

	// Storage / Block / SCSI
	"scsi_", "nvme_", "ata_", "ahci_", "blk_", "dm_", "md_", "sr_", "sg_",
	"ufs_", "spdk_", "pmem_", "zram_", "loop_",

	// Sound / Audio
	"snd_", "alsa_", "sound_", "ac97_", "hda_",

	// Video4Linux / Media
	"v4l2_", "vb2_", "media_", "cec_", "dvb_",

	// Input devices
	"input_", "evdev_", "joydev_", "touch_", "tablet_",

	// Hardware control frameworks
	"gpio_", "pwm_", "leds_", "iio_", "hwmon_",
	"watchdog_", "rtc_", "ptp_", "thermal_", "powercap_",

	// Security subsystems
	"security_", "selinux_", "ima_", "evm_", "apparmor_", "landlock_", "smack_",

	// Platform / Firmware / Buses
	"firmware_", "acpi_", "efi_", "smbios_",
	"i2c_", "spi_", "mtd_", "nand_", "pcie_",

	// Crypto / IPC
	"kdbus_", "af_alg_", "crypto_", "hash_",
}

// extractComplexTypes extracts all complex types used by a syscall.
// It leverages prog.ForeachCallType which automatically handles recursion and circular references.
// Types matching excludedPrefixes or deemed too generic (buffers, primitive arrays) are filtered out.
func extractComplexTypes(call *prog.Syscall) map[typeKey]typeInfo {
	result := make(map[typeKey]typeInfo)
	prog.ForeachCallType(call, func(t prog.Type, ctx *prog.TypeCtx) {
		if shouldSkipType(t) {
			return
		}
		if info, ok := classifyType(t); ok {
			result[info.Key] = info
		}
	})
	return result
}

// shouldSkipType determines if a type should be excluded from analysis.
// Returns true for:
// - Generic buffers (BufferType)
// - Primitive types (IntType, ConstType, etc.)
// - Types with excluded prefixes (btrfs_, bpf_, etc.)
// - Pointers/arrays composed of the above
func shouldSkipType(t prog.Type) bool {
	switch typ := t.(type) {
	case *prog.StructType:
		return hasExcludedPrefix(typ.TemplateName())
	case *prog.UnionType:
		return hasExcludedPrefix(typ.TemplateName())
	case *prog.FlagsType:
		return hasExcludedPrefix(typ.TemplateName())
	case *prog.PtrType:
		// Skip pointers to excluded types
		return shouldSkipType(typ.Elem)
	case *prog.ArrayType:
		// Skip arrays of excluded or primitive types
		return shouldSkipType(typ.Elem)
	case *prog.BufferType:
		// All buffer types are too generic
		return true
	case *prog.IntType, *prog.ConstType, *prog.LenType, *prog.ProcType,
		*prog.CsumType, *prog.VmaType, *prog.ResourceType:
		// Primitive types
		return true
	default:
		return false
	}
}

// hasExcludedPrefix checks if a type name starts with any excluded prefix.
func hasExcludedPrefix(name string) bool {
	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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
