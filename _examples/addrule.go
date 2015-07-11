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

	rule := &audit.AuditRuleData{
		Flags:  audit.AUDIT_FILTER_EXIT,
		Action: audit.AUDIT_ALWAYS,
	}
	rule.SetSyscall(syscall.SYS_RMDIR)
	rule.SetField(audit.AUDIT_PID, 1234, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_UID, 1000, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_EUID, 1000, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_SUID, 1000, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_FSUID, 1000, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_GID, 1000, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_EGID, 1000, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_SGID, 1000, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_FSGID, 1000, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_FILTERKEY, "TEST", audit.AUDIT_EQUAL)
	al.AddRule(rule)

	//al.DelRule(rule)
}
