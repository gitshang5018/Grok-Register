package turnstile

import (
	"os/exec"
	"runtime"
)

// setProcessGroup configures process group so child processes can be killed in bulk.
func setProcessGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	setPlatformProcessGroup(cmd)
}

// killProcessGroup terminates the process and all its subprocesses (e.g. Chrome/Python).
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	killPlatformProcessGroup(cmd)
}

// CleanupOrphanProcesses forcefully purges lingering mint/pool/cloakbrowser processes.
func CleanupOrphanProcesses() {
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/F", "/IM", "python.exe", "/FI", "WINDOWTITLE eq mint*").Run()
		return
	}
	// Unix / Linux
	_ = exec.Command("pkill", "-9", "-f", "turnstile_mint.py").Run()
	_ = exec.Command("pkill", "-9", "-f", "turnstile_pool.py").Run()
	_ = exec.Command("pkill", "-9", "-f", "cloakbrowser").Run()
}
