package main

import (
	"log"
	"os"
	"syscall"

	"github.com/apuigsech/netlink"
	"github.com/apuigsech/netlink/protocols/audit"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	netlink.Logger = logger

	al, _ := audit.OpenLink(0, 0)

	rule := &audit.AuditRuleData{
		Flags:  audit.AUDIT_FILTER_EXIT,
		Action: audit.AUDIT_ALWAYS,
	}
	rule.SetSyscall(syscall.SYS_FORK)
	rule.SetSyscall(syscall.SYS_CLONE)
	al.AddRule(rule)

	st, _ := al.GetStatus()
	logger.Println("  -", st)

	st.Mask = audit.AUDIT_STATUS_ENABLED | audit.AUDIT_STATUS_PID
	st.Enabled = 1
	st.Pid = uint32(os.Getpid())

	al.SetStatus(st)
	logger.Println("  -", st)

	for {
		msgList, _ := al.Reply(0)
		logger.Println("count:", len(msgList))
		for _, msg := range msgList {
			if msg.Header.Type == audit.AUDIT_SYSCALL {
				logger.Printf("%s", msg.Data)
			} else {
				logger.Println(msg)
			}
		}
	}

	al.DelRule(rule)
}
