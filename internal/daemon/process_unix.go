//go:build !windows

package daemon

import (
	"os"
	"os/exec"
	"syscall"
)

// pidAliveSignal is used for the existance probe (signal 0 on Unix).
const pidAliveSignal = syscall.Signal(0)

// requestTerminate sends a graceful SIGTERM.
func requestTerminate(proc *os.Process) {
	_ = proc.Signal(syscall.SIGTERM)
}

// requestKill force-kills.
func requestKill(proc *os.Process) {
	_ = proc.Signal(syscall.SIGKILL)
}

// detachProcess detaches the child from the controlling terminal.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// lockFile takes an advisory exclusive lock (blocking-free).
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// unlockFile releases an advisory lock previously taken by lockFile.
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// pidAliveFallback is unused on Unix (PIDAlive uses signal-0); kept for the
// shared daemon.go signature.
func pidAliveFallback(proc *os.Process) bool {
	return proc != nil
}
