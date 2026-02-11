package preflight

import (
	"runtime"
	"testing"

	"go.uber.org/zap"
)

func TestParseKeyValueFile(t *testing.T) {
	input := `Key1: Value1
Key2:	Value2
Key3: 123
Empty:
NoColon
`
	result := parseKeyValueFile(input)

	tests := []struct {
		key  string
		want string
		ok   bool
	}{
		{"Key1", "Value1", true},
		{"Key2", "Value2", true},
		{"Key3", "123", true},
		{"Empty", "", true},
		{"NoColon", "", false},
		{"Missing", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			val, ok := result[tt.key]
			if ok != tt.ok {
				t.Errorf("key %q: exists=%v, want %v", tt.key, ok, tt.ok)
			}
			if ok && val != tt.want {
				t.Errorf("key %q = %q, want %q", tt.key, val, tt.want)
			}
		})
	}
}

func TestRunOnMacOS(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}

	logger, _ := zap.NewDevelopment()
	err := Run(logger)

	// On macOS, most checks will fail (Linux-only), so Run should return error
	if err == nil {
		t.Error("Run() should fail on macOS (Linux-only checks)")
	}
}

func TestCheckPermissionsNonRoot(t *testing.T) {
	// This test runs as a normal user, so permissions check should fail
	err := checkPermissions()
	if err == nil {
		t.Skip("running as root, skipping non-root test")
	}
	// Should contain a meaningful error message
	if err.Error() == "" {
		t.Error("checkPermissions() returned empty error")
	}
}

func TestCheckHugepageNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux-specific behavior tested separately")
	}
	err := checkHugepage()
	if err == nil {
		t.Error("checkHugepage() should fail on non-Linux")
	}
}

func TestCheckNICDriverNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux-specific behavior tested separately")
	}
	err := checkNICDriver()
	if err == nil {
		t.Error("checkNICDriver() should fail on non-Linux")
	}
}

func TestCheckCPUNUMANonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux-specific behavior tested separately")
	}
	err := checkCPUNUMA()
	if err == nil {
		t.Error("checkCPUNUMA() should fail on non-Linux")
	}
}
