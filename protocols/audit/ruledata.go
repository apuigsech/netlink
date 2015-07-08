package audit

import (
	"errors"
	"unsafe"
)

type AuditRuleData struct {
	Flags       uint32 /* AUDIT_PER_{TASK,CALL}, AUDIT_PREPEND */
	Action      uint32 /* AUDIT_NEVER, AUDIT_POSSIBLE, AUDIT_ALWAYS */
	Field_count uint32
	Mask        [AUDIT_BITMASK_SIZE]uint32 /* syscall(s) affected */
	Fields      [AUDIT_MAX_FIELDS]uint32
	Values      [AUDIT_MAX_FIELDS]uint32
	Fieldflags  [AUDIT_MAX_FIELDS]uint32
	Buflen      uint32 /* total length of string fields */
	Buf         []byte //[0]byte /* string fields buffer */
}

func (rule *AuditRuleData) SetSyscall(scn int) error {
	i := uint32(scn / 32)
	b := 1 << (uint32(scn) - i*32)
	if i > AUDIT_BITMASK_SIZE {
		return errors.New("ouf of range")
	}
	rule.Mask[i] |= uint32(b)
	return nil
}

func (rule *AuditRuleData) toWireFormat() []byte {
	b := make([]byte, int(unsafe.Sizeof(*rule))+int(rule.Buflen))
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rule.Flags
	*(*uint32)(unsafe.Pointer(&b[4:8][0])) = rule.Action
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rule.Field_count
	*(*[AUDIT_BITMASK_SIZE]uint32)(unsafe.Pointer(&b[12:268][0])) = rule.Mask
	*(*[AUDIT_MAX_FIELDS]uint32)(unsafe.Pointer(&b[268:524][0])) = rule.Fields
	*(*[AUDIT_MAX_FIELDS]uint32)(unsafe.Pointer(&b[524:780][0])) = rule.Values
	*(*[AUDIT_MAX_FIELDS]uint32)(unsafe.Pointer(&b[780:1036][0])) = rule.Fieldflags
	*(*uint32)(unsafe.Pointer(&b[1036:1040][0])) = rule.Buflen
	copy(b[1040:1040+rule.Buflen], rule.Buf[:])
	return b
}
