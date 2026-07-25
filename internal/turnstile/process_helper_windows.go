//go:build windows

package turnstile

import (
	"fmt"
	"os/exec"
	"syscall"
)

func setPlatformProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags = syscall.CREATE_NEW_PROCESS_GROUP
}

func killPlatformProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", cmd.Process.Pid)).Run()
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}
