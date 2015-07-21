package audit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"errors"
	"encoding/hex"
)

type EventCallback func(*AuditEvent, chan error, ...interface{})

type AuditEvent struct {
	Timestamp		float64
	Serial			int32
	Info			map[string]interface{}
}

func NewAuditEvent(msg string) (*AuditEvent, error) {
	re := regexp.MustCompile(`^audit\((\d+\.\d+):(\d+)\): (.+)$`)
	data := re.FindStringSubmatch(msg)

	if len(data) != 4 {
		return nil,errors.New("Invalid Message")
	}

	timestamp, err := strconv.ParseFloat(data[1], 64)
	if err != nil {
		return nil,errors.New("Invalid Message")
	}

	serial, err := strconv.ParseInt(data[2], 10, 32)
	if err != nil {
		return nil,errors.New("Invalid Message")
	}	
	
	info := make(map[string]interface{})

	for _, e := range strings.Split(msg, " ") {
		a := strings.Split(e, "=")
		if len(a) == 2 {
			key := a[0]
			var value interface{}
			switch key {
			case "auid", "egid", "euid", "exit", "fsgid", "fsuid", "gid", "item", "items", "pid", "ppid", "sgid", "suid", "ses", "syscall", "uid":
				v,err := strconv.ParseInt(a[1], 10, 32)
				if err != nil {
					value = a[1]
					fmt.Println("Unexpected VALUE", key, value, err)
				} else {
					value = v
				}
			case "comm", "exe", "key":
				a[1] = strings.Trim(a[1], "\x00")
				if a[1][0] == '"' && a[1][len(a[1])-1] == '"' {
					value = strings.Trim(a[1], "\"")
				} else if a[1][0] == '(' && a[1][len(a[1])-1] == ')' {
					// TODO: Process
					value = a[1]
					fmt.Println("Todo VALUE", key, value)
				} else {
					v,err := hex.DecodeString(a[1])
					if err != nil {
						value = a[1]
						fmt.Println("Unexpected VALUE", key, value, err)
					} else {
						value = string(v)
					}	
				}
			case "tty":
				value = a[1]
			case "success":
				if a[1] == "yes" {
					value = true
				} else {
					value = false
				}
			default:
				value = a[1]
				fmt.Println("Unsupported KEY", key, value)
			}
			info[key] = value
		}
	}

	event := &AuditEvent{
		Timestamp:	timestamp,
		Serial:		int32(serial),
		Info:		info,
	}

	return event,nil
}

func (al *AuditNLSocket) StartEventMonitor(cb EventCallback, ec chan error, args ...interface{}) {
	al.GetAuditEvents(true)
	go func() {
		for {
			msgList, _ := al.Reply(0)
			// TODO: Implement polling.
			for _, msg := range msgList {
				if msg.Header.Type == AUDIT_SYSCALL {
					event,_ := NewAuditEvent(string(msg.Data))
					cb(event, ec, args...)
				}
			}
		}
	}()
}