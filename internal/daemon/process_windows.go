//go:build windows

package daemon

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// pidAliveSignal placeholder: Windows cannot use a 0-signal probe, so
// PIDAlive uses windows.OpenProcess instead. This constant is only here to
// satisfy the shared daemon.go signature; it is not passed to Signal.
const pidAliveSignal = syscall.Signal(0)

// pidAlive reports whether a Windows process handle can be opened.
// On Windows proc.Signal(0) is unsupported, so we probe via OpenProcess.
func pidAliveFallback(proc *os.Process) bool {
	if proc == nil {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(proc.Pid))
	if err != nil {
		return false
	}
	windows.CloseHandle(handle)
	return true
}

// requestTerminate closes the process gracefully via WM_CLOSE-equivalent.
// We use TerminateProcess with a 0 exit code is heavy; prefer taskkill (no /F)
// so the worker gets a chance to drain before being killed by Stop's Deadline.
func requestTerminate(proc *os.Process) {
	if proc == nil {
		return
	}
	_ = exec.Command("taskkill", "/PID", itoa(proc.Pid)).Run()
}

// requestKill force-terminates the process tree.
func requestKill(proc *os.Process) {
	if proc == nil {
		return
	}
	_ = exec.Command("taskkill", "/F", "/T", "/PID", itoa(proc.Pid)).Run()
	_ = proc.Kill()
}

// detachProcess starts the child detached from the current console, so the
// parent console close does not kill the background worker.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
}

// lockFile takes an exclusive byte-range lock via LockFileEx (blocking-free).
func lockFile(f *os.File) error {
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &windows.Overlapped{},
	)
}

// unlockFile releases the byte-range lock taken by lockFile.
func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
