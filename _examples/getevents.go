package main 

import (
	"syscall"
	"os"
	"log"
	"../protocols/audit"
)



func main() {
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
	st.Pid = uint32(os.Getpid())


	al.SetStatus(st); log.Println("  -", st)

	for {
		msgList,_ := al.Reply(0)
		log.Println("count:", len(msgList))
		for _,msg := range msgList {
			if msg.Header.Type == audit.AUDIT_SYSCALL {
				log.Printf("%s", msg.Data)
			} else {
				log.Println(msg)
			}
		}
	}

	al.DelRule(rule)
}