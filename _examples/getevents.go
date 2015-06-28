package main 

import (
	"syscall"
	"os"
	"log"
	"../protocols/audit"
)

func main() {
	log.Println("getevents example")
	al,_ := audit.OpenLink(0,0)

	rule := &audit.AuditRuleData {
		Flags:		audit.AUDIT_FILTER_EXIT,
		Action:		audit.AUDIT_ALWAYS,
	}
	rule.SetSyscall(syscall.SYS_FORK)
	rule.SetSyscall(syscall.SYS_CLONE)
	al.AddRule(rule)

	st,_ := al.GetStatus(); log.Println("  -", st)

	st.Mask = audit.AUDIT_STATUS_ENABLED | audit.AUDIT_STATUS_PID
	st.Enabled = 1
	st.Failure = 0
	st.Pid = uint32(os.Getpid())
	st.Rate_limit = 0
	st.Backlog_limit = 0
	st.Lost = 0
	st.Backlog = 0

	al.SetStatus(st); log.Println("  -", st)

	for {
		al.Reply(0)
	}

	//al.DelRule(rule)
}