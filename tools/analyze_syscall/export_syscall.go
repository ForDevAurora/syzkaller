package prog

func ExportCreatesResources(call *Syscall) []*ResourceDesc {
	return call.createsResources
}
