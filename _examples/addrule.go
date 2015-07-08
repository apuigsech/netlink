package main

import (
	//"log"
	//"time"
	//	"syscall"
	//	netlink "../"
	"../protocols/audit"
	"syscall"
)

func main() {
	al, _ := audit.OpenLink(0, 0)
	al.Request(audit.AUDIT_LIST_RULES, []byte(""))

	rule := &audit.AuditRuleData{
		Flags:  audit.AUDIT_FILTER_EXIT,
		Action: audit.AUDIT_ALWAYS,
	}
	rule.SetSyscall(syscall.SYS_RMDIR)
	al.AddRule(rule)

	rule = &audit.AuditRuleData{
		Flags:  audit.AUDIT_FILTER_EXIT,
		Action: audit.AUDIT_ALWAYS,
	}
	rule.SetSyscall(syscall.SYS_FORK)
	al.AddRule(rule)

	//al.DelRule(rule)
}
