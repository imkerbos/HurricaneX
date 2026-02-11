package preflight

import "fmt"

// Check represents a single pre-flight check.
type Check struct {
	Name    string
	RunFunc func() error
}

// Run executes all pre-flight checks and reports results.
func Run() error {
	checks := []Check{
		{Name: "hugepage", RunFunc: checkHugepage},
		{Name: "nic_driver", RunFunc: checkNICDriver},
		{Name: "cpu_numa", RunFunc: checkCPUNUMA},
		{Name: "permissions", RunFunc: checkPermissions},
		{Name: "libraries", RunFunc: checkLibraries},
	}

	passed := 0
	failed := 0

	for _, c := range checks {
		if err := c.RunFunc(); err != nil {
			fmt.Printf("  FAIL: %s — %v\n", c.Name, err)
			failed++
		} else {
			fmt.Printf("  OK:   %s\n", c.Name)
			passed++
		}
	}

	fmt.Printf("\nPreflight: %d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return fmt.Errorf("%d preflight check(s) failed", failed)
	}
	return nil
}

func checkHugepage() error {
	// TODO: Check /sys/kernel/mm/hugepages/ or /proc/meminfo
	return fmt.Errorf("not implemented — hugepage check skipped")
}

func checkNICDriver() error {
	// TODO: Check for igb_uio or vfio-pci driver binding
	return fmt.Errorf("not implemented — NIC driver check skipped")
}

func checkCPUNUMA() error {
	// TODO: Check NUMA topology and CPU isolation
	return fmt.Errorf("not implemented — CPU/NUMA check skipped")
}

func checkPermissions() error {
	// TODO: Check for root or CAP_NET_ADMIN
	return fmt.Errorf("not implemented — permissions check skipped")
}

func checkLibraries() error {
	// TODO: Check for libdpdk, libnuma, OpenSSL
	return fmt.Errorf("not implemented — library check skipped")
}
