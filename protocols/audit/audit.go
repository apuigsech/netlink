package audit

import (
	//"log"
	"syscall"
	"unsafe"
	"errors"
	netlink "../../"
)

const (
	MAX_AUDIT_MESSAGE_LENGTH = 8970
	AUDIT_GET                = 1000
	AUDIT_SET                = 1001 /* Set status (enable/disable/auditd) */
	AUDIT_LIST               = 1002
	AUDIT_LIST_RULES         = 1013
	AUDIT_ADD_RULE           = 1011 /* Add syscall filtering rule */
	AUDIT_FIRST_USER_MSG     = 1100 /* Userspace messages mostly uninteresting to kernel */
	AUDIT_MAX_FIELDS         = 64
	AUDIT_BITMASK_SIZE       = 64
	AUDIT_GET_FEATURE        = 1019
	//Rule Flags
	AUDIT_FILTER_USER  = 0x00 /* Apply rule to user-generated messages */
	AUDIT_FILTER_TASK  = 0x01 /* Apply rule at task creation (not syscall) */
	AUDIT_FILTER_ENTRY = 0x02 /* Apply rule at syscall entry */
	AUDIT_FILTER_WATCH = 0x03 /* Apply rule to file system watches */
	AUDIT_FILTER_EXIT  = 0x04 /* Apply rule at syscall exit */
	AUDIT_FILTER_TYPE  = 0x05 /* Apply rule at audit_log_start */
	/* These are used in filter control */
	AUDIT_FILTER_MASK  = 0x07 /* Mask to get actual filter */
	AUDIT_FILTER_UNSET = 0x80 /* This value means filter is unset */

	/* Rule actions */
	AUDIT_NEVER    = 0 /* Do not build context if rule matches */
	AUDIT_POSSIBLE = 1 /* Build context if rule matches  */
	AUDIT_ALWAYS   = 2 /* Generate audit record if rule matches */
	AUDIT_DEL_RULE = 1012

	/*Audit Message Types */
	AUDIT_SYSCALL       = 1300 /* Syscall event */
	AUDIT_PATH          = 1302 /* Filename path information */
	AUDIT_IPC           = 1303 /* IPC record */
	AUDIT_SOCKETCALL    = 1304 /* sys_socketcall arguments */
	AUDIT_CONFIG_CHANGE = 1305 /* Audit system configuration change */
	AUDIT_SOCKADDR      = 1306 /* sockaddr copied as syscall arg */
	AUDIT_CWD           = 1307 /* Current working directory */
	AUDIT_EXECVE        = 1309 /* execve arguments */
	AUDIT_EOE           = 1320 /* End of multi-record event */

	/* Rule fields */
	/* These are useful when checking the
	 * task structure at task creation time
	 * (AUDIT_PER_TASK).  */
	AUDIT_PID                   = 0
	AUDIT_UID                   = 1
	AUDIT_EUID                  = 2
	AUDIT_SUID                  = 3
	AUDIT_FSUID                 = 4
	AUDIT_GID                   = 5
	AUDIT_EGID                  = 6
	AUDIT_SGID                  = 7
	AUDIT_FSGID                 = 8
	AUDIT_LOGINUID              = 9
	AUDIT_OBJ_GID               = 110
	AUDIT_OBJ_UID               = 109
	AUDIT_EXIT                  = 103
	AUDIT_PERS                  = 10
	AUDIT_FILTER_EXCLUDE        = 0x05
	AUDIT_ARCH                  = 11
	PATH_MAX                    = 4096
	AUDIT_MSGTYPE               = 12
	AUDIT_MAX_KEY_LEN           = 256
	AUDIT_PERM                  = 106
	AUDIT_FILTERKEY             = 210
	AUDIT_SUBJ_USER             = 13 /* security label user */
	AUDIT_SUBJ_ROLE             = 14 /* security label role */
	AUDIT_SUBJ_TYPE             = 15 /* security label type */
	AUDIT_SUBJ_SEN              = 16 /* security label sensitivity label */
	AUDIT_SUBJ_CLR              = 17 /* security label clearance label */
	AUDIT_PPID                  = 18
	AUDIT_OBJ_USER              = 19
	AUDIT_OBJ_ROLE              = 20
	AUDIT_OBJ_TYPE              = 21
	AUDIT_WATCH                 = 105
	AUDIT_DIR                   = 107
	AUDIT_OBJ_LEV_LOW           = 22
	AUDIT_OBJ_LEV_HIGH          = 23
	AUDIT_LOGINUID_SET          = 24
	AUDIT_DEVMAJOR              = 100
	AUDIT_INODE                 = 102
	AUDIT_SUCCESS               = 104
	AUDIT_PERM_EXEC             = 1
	AUDIT_PERM_WRITE            = 2
	AUDIT_PERM_READ             = 4
	AUDIT_PERM_ATTR             = 8
	AUDIT_FILETYPE              = 108
	AUDIT_ARG0                  = 200
	AUDIT_ARG1                  = (AUDIT_ARG0 + 1)
	AUDIT_ARG2                  = (AUDIT_ARG0 + 2)
	AUDIT_ARG3                  = (AUDIT_ARG0 + 3)
	AUDIT_BIT_MASK              = 0x08000000
	AUDIT_LESS_THAN             = 0x10000000
	AUDIT_GREATER_THAN          = 0x20000000
	AUDIT_NOT_EQUAL             = 0x30000000
	AUDIT_EQUAL                 = 0x40000000
	AUDIT_BIT_TEST              = (AUDIT_BIT_MASK | AUDIT_EQUAL)
	AUDIT_LESS_THAN_OR_EQUAL    = (AUDIT_LESS_THAN | AUDIT_EQUAL)
	AUDIT_GREATER_THAN_OR_EQUAL = (AUDIT_GREATER_THAN | AUDIT_EQUAL)
	AUDIT_OPERATORS             = (AUDIT_EQUAL | AUDIT_NOT_EQUAL | AUDIT_BIT_MASK)
	/* Status symbols */
	/* Mask values */
	AUDIT_STATUS_ENABLED       = 0x0001
	AUDIT_STATUS_FAILURE       = 0x0002
	AUDIT_STATUS_PID           = 0x0004
	AUDIT_STATUS_RATE_LIMIT    = 0x0008
	AUDIT_STATUS_BACKLOG_LIMIT = 0x0010
	/* Failure-to-log actions */
	AUDIT_FAIL_SILENT = 0
	AUDIT_FAIL_PRINTK = 1
	AUDIT_FAIL_PANIC  = 2

	/* distinguish syscall tables */
	__AUDIT_ARCH_64BIT  = 0x80000000
	__AUDIT_ARCH_LE     = 0x40000000
	AUDIT_ARCH_ALPHA    = (EM_ALPHA | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
	AUDIT_ARCH_ARM      = (EM_ARM | __AUDIT_ARCH_LE)
	AUDIT_ARCH_ARMEB    = (EM_ARM)
	AUDIT_ARCH_CRIS     = (EM_CRIS | __AUDIT_ARCH_LE)
	AUDIT_ARCH_FRV      = (EM_FRV)
	AUDIT_ARCH_I386     = (EM_386 | __AUDIT_ARCH_LE)
	AUDIT_ARCH_IA64     = (EM_IA_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
	AUDIT_ARCH_M32R     = (EM_M32R)
	AUDIT_ARCH_M68K     = (EM_68K)
	AUDIT_ARCH_MIPS     = (EM_MIPS)
	AUDIT_ARCH_MIPSEL   = (EM_MIPS | __AUDIT_ARCH_LE)
	AUDIT_ARCH_MIPS64   = (EM_MIPS | __AUDIT_ARCH_64BIT)
	AUDIT_ARCH_MIPSEL64 = (EM_MIPS | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
	//	AUDIT_ARCH_OPENRISC = (EM_OPENRISC)
	//	AUDIT_ARCH_PARISC   = (EM_PARISC)
	//	AUDIT_ARCH_PARISC64 = (EM_PARISC | __AUDIT_ARCH_64BIT)
	AUDIT_ARCH_PPC     = (EM_PPC)
	AUDIT_ARCH_PPC64   = (EM_PPC64 | __AUDIT_ARCH_64BIT)
	AUDIT_ARCH_S390    = (EM_S390)
	AUDIT_ARCH_S390X   = (EM_S390 | __AUDIT_ARCH_64BIT)
	AUDIT_ARCH_SH      = (EM_SH)
	AUDIT_ARCH_SHEL    = (EM_SH | __AUDIT_ARCH_LE)
	AUDIT_ARCH_SH64    = (EM_SH | __AUDIT_ARCH_64BIT)
	AUDIT_ARCH_SHEL64  = (EM_SH | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
	AUDIT_ARCH_SPARC   = (EM_SPARC)
	AUDIT_ARCH_SPARC64 = (EM_SPARCV9 | __AUDIT_ARCH_64BIT)
	AUDIT_ARCH_X86_64  = (EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
	///Temporary Solution need to add linux/elf-em.h
	EM_NONE  = 0
	EM_M32   = 1
	EM_SPARC = 2
	EM_386   = 3
	EM_68K   = 4
	EM_88K   = 5
	EM_486   = 6 /* Perhaps disused */
	EM_860   = 7
	EM_MIPS  = 8 /* MIPS R3000 (officially, big-endian only) */
	/* Next two are historical and binaries and
	   modules of these types will be rejected by
	   Linux.  */
	EM_MIPS_RS3_LE = 10 /* MIPS R3000 little-endian */
	EM_MIPS_RS4_BE = 10 /* MIPS R4000 big-endian */

	EM_PARISC      = 15     /* HPPA */
	EM_SPARC32PLUS = 18     /* Sun's "v8plus" */
	EM_PPC         = 20     /* PowerPC */
	EM_PPC64       = 21     /* PowerPC64 */
	EM_SPU         = 23     /* Cell BE SPU */
	EM_ARM         = 40     /* ARM 32 bit */
	EM_SH          = 42     /* SuperH */
	EM_SPARCV9     = 43     /* SPARC v9 64-bit */
	EM_IA_64       = 50     /* HP/Intel IA-64 */
	EM_X86_64      = 62     /* AMD x86-64 */
	EM_S390        = 22     /* IBM S/390 */
	EM_CRIS        = 76     /* Axis Communications 32-bit embedded processor */
	EM_V850        = 87     /* NEC v850 */
	EM_M32R        = 88     /* Renesas M32R */
	EM_MN10300     = 89     /* Panasonic/MEI MN10300, AM33 */
	EM_BLACKFIN    = 106    /* ADI Blackfin Processor */
	EM_TI_C6000    = 140    /* TI C6X DSPs */
	EM_AARCH64     = 183    /* ARM 64 bit */
	EM_FRV         = 0x5441 /* Fujitsu FR-V */
	EM_AVR32       = 0x18ad /* Atmel AVR32 */

	/*
	 * This is an interim value that we will use until the committee comes
	 * up with a final number.
	 */
	EM_ALPHA = 0x9026

	/* Bogus old v850 magic number, used by old tools. */
	EM_CYGNUS_V850 = 0x9080
	/* Bogus old m32r magic number, used by old tools. */
	EM_CYGNUS_M32R = 0x9041
	/* This is the old interim value for S/390 architecture */
	EM_S390_OLD = 0xA390
	/* Also Panasonic/MEI MN10300, AM33 */
	EM_CYGNUS_MN10300 = 0xbeef
	//AUDIT_ARCH determination purpose
	_UTSNAME_LENGTH          = 65
	_UTSNAME_DOMAIN_LENGTH   = _UTSNAME_LENGTH
	_UTSNAME_NODENAME_LENGTH = _UTSNAME_DOMAIN_LENGTH
)

type AuditNLSocket netlink.NetlinkSocket

type AuditStatus struct {
	Mask          uint32 /* Bit mask for valid entries */
	Enabled       uint32 /* 1 = enabled, 0 = disabled */
	Failure       uint32 /* Failure-to-log action */
	Pid           uint32 /* pid of auditd process */
	Rate_limit    uint32 /* messages rate limit (per second) */
	Backlog_limit uint32 /* waiting messages limit */
	Lost          uint32 /* messages lost */
	Backlog       uint32 /* messages waiting in queue */
}

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


func (st *AuditStatus) toWireFormat() []byte {
	b := make([]byte, 8*4)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = st.Mask
	*(*uint32)(unsafe.Pointer(&b[4:8][0])) = st.Enabled
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = st.Failure
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = st.Pid
	*(*uint32)(unsafe.Pointer(&b[16:20][0])) = st.Rate_limit
	*(*uint32)(unsafe.Pointer(&b[20:24][0])) = st.Backlog_limit
	*(*uint32)(unsafe.Pointer(&b[24:28][0])) = st.Lost
	*(*uint32)(unsafe.Pointer(&b[28:32][0])) = st.Backlog
	return b
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

// TODO: Function for AuditMessage.
func ParseAuditMessage(msg string) map[string]string {
	ret := make(map[string]string)
	for _,e := range strings.Split(msg, " ") {
		a := strings.Split(e, "=")
		log.Println(a)
		if len(a) == 2 {
			ret[a[0]] = a[1]
		}
	}
	return ret
}


func AuditStatusfromWireFormat(data []byte) (*AuditStatus) {
	return (*AuditStatus)(unsafe.Pointer(&data[0:32][0]))
}


func (rule *AuditRuleData) SetSyscall(scn int) error {
	i := uint32(scn / 32)
	b := 1 << (uint32(scn) - i * 32)
	if i > AUDIT_BITMASK_SIZE {
		return errors.New("ouf of range")
	}
	rule.Mask[i] |= uint32(b)
	return nil
}


func nlmAlignOf(msglen int) int {
	return (msglen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}


func ParseAuditNetlinkMessage(b []byte) ([]netlink.NetlinkMessage, error) {
	var msgList []netlink.NetlinkMessage

	h := (*syscall.NlMsghdr)(unsafe.Pointer(&b[0]))
	if int(h.Len) < syscall.NLMSG_HDRLEN || int(h.Len) > len(b) {
		return []netlink.NetlinkMessage{}, errors.New("ouf of range")
	}

	h.Len = uint32(nlmAlignOf(int(h.Len)))

	msg := netlink.NetlinkMessage{Header: *h, Data: b[syscall.NLMSG_HDRLEN:h.Len+syscall.NLMSG_HDRLEN]}
	msgList = append(msgList, msg)

	return msgList, nil
}


func OpenLink(group int, pid int) (*AuditNLSocket, error) {
	 nl, err := netlink.OpenLink(syscall.NETLINK_AUDIT, group, pid)
	 if err != nil {
	 		return nil, err
	 }
	 //syscall.Syscall(syscall.SYS_FCNTL, nl.sfd, syscall.F_SETFD, syscall.FD_CLOEXEC)
	 return (*AuditNLSocket)(nl),nil
}


func (al *AuditNLSocket) CloseLink() (error) {
	nl := (*netlink.NetlinkSocket)(al)
	return nl.CloseLink()
}


func (al *AuditNLSocket) RecvMessages(sz int, sockflags int) ([]netlink.NetlinkMessage, error) {
	nl := (*netlink.NetlinkSocket)(al)

	buf, err := nl.RecvMessagesRaw(sz, sockflags)
	if err != nil {
		return nil,err
	}

	return ParseAuditNetlinkMessage(buf)
}


func (al *AuditNLSocket) Request(msgtype int, flags int, data []byte, sockflags int, ack bool) error {
	nl := (*netlink.NetlinkSocket)(al)

	msg := &netlink.NetlinkMessage{}
	msg.Header.Type = uint16(msgtype)
	msg.Header.Flags = uint16(flags | syscall.NLM_F_REQUEST)
	msg.Data = data

	return nl.SendMessage(msg, sockflags, ack)
}


func (al *AuditNLSocket) Reply(sockflags int) ([]netlink.NetlinkMessage, error) {
	//nl := (*netlink.NetlinkSocket)(al)
	return al.RecvMessages(MAX_AUDIT_MESSAGE_LENGTH, sockflags)
}


func (al *AuditNLSocket) RequestWithReply(msgtype int, flags int, data []byte) ([]netlink.NetlinkMessage, error) {
	err := al.Request(msgtype, flags, data, 0, false)
	if err != nil {
		return []netlink.NetlinkMessage{}, nil
	}

	for {
		msgList, err := al.Reply(0)
		if err != nil {
			return []netlink.NetlinkMessage{},err
		}
		m := msgList[0]
		if m.Header.Type == uint16(msgtype) {
			return msgList, nil
		}
	}
}


func (al *AuditNLSocket) GetStatus() (*AuditStatus, error) {
	msgList, err := al.RequestWithReply(AUDIT_GET, 0, []byte(""))
	if err != nil {
		return nil,err
	}
	m := msgList[0]
	st := AuditStatusfromWireFormat(m.Data)
	return st,nil
}


func (al *AuditNLSocket) SetStatus(st *AuditStatus) error {
	return al.Request(AUDIT_SET, 0, st.toWireFormat(), 0, false)
}


func (al *AuditNLSocket) AddRule(rule *AuditRuleData) error {
	return al.Request(AUDIT_ADD_RULE, 0, rule.toWireFormat(), 0, false)
}



func (al *AuditNLSocket) DelRule(rule *AuditRuleData) error {
	return al.Request(AUDIT_DEL_RULE, 0, rule.toWireFormat(), 0, false)
}


func (al *AuditNLSocket) ListRules() error {
	return nil
}


