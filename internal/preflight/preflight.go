package preflight

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// Check represents a single pre-flight check.
type Check struct {
	Name    string
	RunFunc func() error
}

// Result holds the outcome of a single check.
type Result struct {
	Name   string
	Passed bool
	Err    error
}

// Run executes all pre-flight checks and reports results.
func Run(logger *zap.Logger) error {
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
			logger.Warn("preflight check failed",
				zap.String("check", c.Name),
				zap.Error(err),
			)
			failed++
		} else {
			logger.Info("preflight check passed",
				zap.String("check", c.Name),
			)
			passed++
		}
	}

	logger.Info("preflight summary",
		zap.Int("passed", passed),
		zap.Int("failed", failed),
	)

	if failed > 0 {
		return fmt.Errorf("%d preflight check(s) failed", failed)
	}
	return nil
}

// checkHugepage verifies hugepage configuration.
// On Linux: reads /proc/meminfo and /sys/kernel/mm/hugepages/.
// On non-Linux: skips with a note.
func checkHugepage() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("hugepage check skipped on %s (Linux only)", runtime.GOOS)
	}

	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return fmt.Errorf("read /proc/meminfo: %w", err)
	}

	info := parseKeyValueFile(string(data))

	totalStr, ok := info["HugePages_Total"]
	if !ok {
		return fmt.Errorf("HugePages_Total not found in /proc/meminfo")
	}
	total, err := strconv.Atoi(strings.TrimSpace(totalStr))
	if err != nil {
		return fmt.Errorf("parse HugePages_Total: %w", err)
	}
	if total == 0 {
		return fmt.Errorf("no hugepages configured (HugePages_Total=0). " +
			"Fix: echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages " +
			"or add hugepagesz=1G hugepages=32 to kernel boot params")
	}

	freeStr, ok := info["HugePages_Free"]
	if ok {
		free, _ := strconv.Atoi(strings.TrimSpace(freeStr))
		if free == 0 {
			return fmt.Errorf("hugepages configured (%d total) but none free — all in use or not mounted. "+
				"Fix: mount -t hugetlbfs nodev /dev/hugepages", total)
		}
	}

	return nil
}

// checkNICDriver verifies DPDK-compatible NIC driver binding.
func checkNICDriver() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("NIC driver check skipped on %s (Linux only)", runtime.GOOS)
	}

	// Check if vfio-pci or igb_uio module is loaded
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return fmt.Errorf("read /proc/modules: %w", err)
	}

	modules := string(data)
	hasVFIO := strings.Contains(modules, "vfio_pci")
	hasIGB := strings.Contains(modules, "igb_uio")

	if !hasVFIO && !hasIGB {
		return fmt.Errorf("no DPDK-compatible NIC driver loaded (need vfio-pci or igb_uio). " +
			"Fix: modprobe vfio-pci")
	}

	// Check if dpdk-devbind.py is available
	if _, err := exec.LookPath("dpdk-devbind.py"); err != nil {
		// Also try dpdk-devbind (without .py)
		if _, err := exec.LookPath("dpdk-devbind"); err != nil {
			return fmt.Errorf("dpdk-devbind.py not found in PATH. " +
				"Fix: install DPDK and ensure dpdk-devbind.py is in PATH")
		}
	}

	return nil
}

// checkCPUNUMA verifies CPU isolation and NUMA topology.
func checkCPUNUMA() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("CPU/NUMA check skipped on %s (Linux only)", runtime.GOOS)
	}

	// Check for isolated CPUs
	data, err := os.ReadFile("/sys/devices/system/cpu/isolated")
	if err != nil {
		return fmt.Errorf("read CPU isolation info: %w", err)
	}

	isolated := strings.TrimSpace(string(data))
	if isolated == "" {
		return fmt.Errorf("no isolated CPUs detected. " +
			"Fix: add isolcpus=2-15 to kernel boot params for DPDK dedicated cores")
	}

	// Check NUMA node count
	entries, err := os.ReadDir("/sys/devices/system/node")
	if err != nil {
		// NUMA info not available, not fatal
		return nil
	}

	nodeCount := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "node") {
			nodeCount++
		}
	}

	if nodeCount == 0 {
		return fmt.Errorf("no NUMA nodes detected")
	}

	return nil
}

// checkPermissions verifies root or CAP_NET_ADMIN capability.
func checkPermissions() error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	if u.Uid == "0" {
		return nil // root
	}

	if runtime.GOOS != "linux" {
		return fmt.Errorf("not running as root (uid=%s). "+
			"DPDK requires root or CAP_NET_ADMIN on Linux", u.Uid)
	}

	// Check for CAP_NET_ADMIN via /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("not running as root and cannot read capabilities: %w", err)
	}

	info := parseKeyValueFile(string(data))
	capEff, ok := info["CapEff"]
	if !ok {
		return fmt.Errorf("not running as root (uid=%s) and cannot determine capabilities", u.Uid)
	}

	// CAP_NET_ADMIN is bit 12. Parse hex capability mask.
	capVal, err := strconv.ParseUint(strings.TrimSpace(capEff), 16, 64)
	if err != nil {
		return fmt.Errorf("parse CapEff: %w", err)
	}

	const capNetAdmin = 1 << 12
	if capVal&capNetAdmin == 0 {
		return fmt.Errorf("not running as root (uid=%s) and missing CAP_NET_ADMIN. "+
			"Fix: run as root or setcap cap_net_admin+ep <binary>", u.Uid)
	}

	return nil
}

// checkLibraries verifies required shared libraries are available.
func checkLibraries() error {
	libs := []struct {
		name    string
		pkgName string
		check   func() error
	}{
		{
			name:    "libdpdk",
			pkgName: "libdpdk",
			check: func() error {
				return checkPkgConfig("libdpdk")
			},
		},
		{
			name:    "libnuma",
			pkgName: "numa",
			check: func() error {
				// Try pkg-config first, then ldconfig
				if err := checkPkgConfig("numa"); err == nil {
					return nil
				}
				return checkLdconfig("libnuma")
			},
		},
		{
			name:    "OpenSSL",
			pkgName: "openssl",
			check: func() error {
				return checkPkgConfig("openssl")
			},
		},
	}

	var missing []string
	for _, lib := range libs {
		if err := lib.check(); err != nil {
			missing = append(missing, lib.name)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing libraries: %s. "+
			"Fix: install via package manager (apt/yum) or build from source",
			strings.Join(missing, ", "))
	}

	return nil
}

// --- helpers ---

func checkPkgConfig(pkg string) error {
	cmd := exec.Command("pkg-config", "--exists", pkg)
	return cmd.Run()
}

func checkLdconfig(lib string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%s: ldconfig check only available on Linux", lib)
	}
	out, err := exec.Command("ldconfig", "-p").Output()
	if err != nil {
		return fmt.Errorf("run ldconfig: %w", err)
	}
	if !strings.Contains(string(out), lib) {
		return fmt.Errorf("%s not found in ldconfig cache", lib)
	}
	return nil
}

// parseKeyValueFile parses lines like "Key: Value" or "Key:\tValue".
func parseKeyValueFile(content string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			result[key] = val
		}
	}
	return result
}
