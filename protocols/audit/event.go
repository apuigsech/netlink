package audit

import (
	"regexp"
	"strings"
	"encoding/hex"
	"errors"
	"strconv"
)


type EventCallback func(*AuditEvent, chan error, ...interface{})


type AuditEventChunk struct {
	Raw					string

	Timestamp			float64
	Serial				int
	Info 				map[string]string
}

type AuditEvent struct {
	Timestamp			float64
	Serial				int
	Chunks				[]*AuditEventChunk
}



func ParseKeyValue(str string) (map[string]string) {
	re_keyvalue := regexp.MustCompile(`((?:\\.|[^= ]+)*)=("(?:\\.|[^"\\]+)*"|(?:\\.|[^ "\\]+)*)`)
	re_quotedstring := regexp.MustCompile(`".+"`)

	a := re_keyvalue.FindAllStringSubmatch(str, -1)
	m := make(map[string]string)

	for _,e := range(a) {
		key := e[1]
		value := e[2]
		if re_quotedstring.MatchString(value) {
			value = strings.Trim(value, "\"")
		}
		m[key] = value
	}

	return m
}


func ParseAuditKeyValue(str string) (map[string]string) {
	audit_key_string := map[string]bool{
		"name":true,
	}

	m := ParseKeyValue(str)

	for key, value := range(m) {
		if audit_key_string[key] {
			re_quotedstring := regexp.MustCompile(`".+"`)
			if re_quotedstring.MatchString(value) {
				value = strings.Trim(value, "\"")
			} else {
				v,err := hex.DecodeString(value)
				if err == nil {
					m[key] = string(v)
				}
			}
		}
	}

	return m
}


func SplitAuditEvent(str string) (float64, int, string, error) {
	re := regexp.MustCompile(`^audit\((\d+\.\d+):(\d+)\): (.+)$`)
	a := re.FindStringSubmatch(str)

	if len(a) != 4 {
		return 0,0,"",errors.New("Invalid Message")
	}

	timestamp, err := strconv.ParseFloat(a[1], 64)
	if err != nil {
		return 0,0,"",errors.New("Invalid Message")
	}

	serial, err := strconv.ParseInt(a[2], 10, 32)
	if err != nil {
		return 0,0,"",errors.New("Invalid Message")
	}

	info := a[3]

	return timestamp, int(serial), info, nil
}


func ParseAuditMessage(str string) (float64, int, map[string]string, error) {
	timestamp, serial, info_str, err := SplitAuditEvent(str)
	if err != nil {
		return 0,0,map[string]string{},err
	}

	info := ParseAuditKeyValue(info_str)	

	return timestamp, serial, info, nil
}


func NewAuditEventChunk(msg string) (*AuditEventChunk, error) {
	timestamp, serial, info, err := ParseAuditMessage(msg)
	if err != nil {
		return nil, err
	}

	aec := &AuditEventChunk{
		Raw:		msg,	
		Timestamp:	timestamp,
		Serial:		serial,
		Info:		info,
	}

	return aec,nil
}


func NewAuditEvent() (*AuditEvent, error) {
	ae := &AuditEvent{
		Timestamp:	0,
		Serial:		0,
		Chunks:		make([]*AuditEventChunk, 0),
	}

	return ae,nil
}


func (ae *AuditEvent)AddChunk(aec *AuditEventChunk) (error) {

	if len(ae.Chunks) != 0 && (ae.Timestamp != aec.Timestamp || ae.Serial != aec.Serial) {
		return errors.New("Unmatched Chunk")
	} 

	ae.Chunks = append(ae.Chunks, aec)

	return nil
}


func (ae *AuditEvent)Update(msg string) (error) {
	aec, err := NewAuditEventChunk(msg)
	if err != nil {
		return err
	}

	err = ae.AddChunk(aec)
	if err != nil {
		return err
	}

	return nil
}


func (ae *AuditEvent)GetValue(key string) (string, bool) {
	for _, aec := range ae.Chunks {
		if value, ok := aec.Info[key]; ok {
			return value,true
		}
	}
	return "",false
}

func (ae *AuditEvent)GetValueString(key string) (string, bool) {
	return ae.GetValue(key)
}


func (ae *AuditEvent)GetValueInt(key string, base int) (int, bool) {
	if value_str,ok := ae.GetValue(key); ok {
		value,err := strconv.ParseInt(value_str, base, 64)
		if err == nil {
			return int(value),true
		}
	}
	return 0,false
}



func (al *AuditNLSocket) StartEventMonitor(cb EventCallback, ec chan error, args ...interface{}) {
	al.GetAuditEvents(true)
	go func() {
		var ae_queue map[int]*AuditEvent
		ae_queue = make(map[int]*AuditEvent)
		for {
			select {
			default:
				msgList, _ := al.Reply(0)
				for _,msg := range msgList {
					aec,err := NewAuditEventChunk(string(msg.Data))
					if err != nil {
						continue
					}
					ae,ok := ae_queue[aec.Serial]
					if ok {
						ae.AddChunk(aec)
					} else {
						ae,_ := NewAuditEvent()
						ae.AddChunk(aec)
						ae_queue[aec.Serial] = ae
					}

					if msg.Header.Type == AUDIT_EOE {
						cb(ae_queue[aec.Serial], ec, args...)
						delete(ae_queue, aec.Serial)
					}
				}
			}
		}
	}()
}
