package audit

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"github.com/apuigsech/netlink"
)

type AuditNLSocket netlink.NetlinkSocket


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

	msg := netlink.NetlinkMessage{Header: *h, Data: b[syscall.NLMSG_HDRLEN : h.Len+syscall.NLMSG_HDRLEN]}
	msgList = append(msgList, msg)

	return msgList, nil
}

func OpenLink(group, pid uint32) (*AuditNLSocket, error) {
	nl, err := netlink.OpenLink(syscall.NETLINK_AUDIT, group, pid)
	if err != nil {
		return nil, err
	}
	// syscall.Syscall(syscall.SYS_FCNTL, nl.sfd, syscall.F_SETFD, syscall.FD_CLOEXEC)

	return (*AuditNLSocket)(nl), nil
}

func (al *AuditNLSocket) CloseLink() error {
	nl := (*netlink.NetlinkSocket)(al)
	return nl.CloseLink()
}

func (al *AuditNLSocket) RecvMessages(sz int, sockflags int) ([]netlink.NetlinkMessage, error) {
	nl := (*netlink.NetlinkSocket)(al)
	buf, err := nl.RecvMessagesRaw(sz, sockflags)
	if err != nil {
		return nil, err
	}

	return ParseAuditNetlinkMessage(buf)
}

func (al *AuditNLSocket) Request(msgtype, flags uint16, data []byte, sockflags int, ack bool) error {
	nl := (*netlink.NetlinkSocket)(al)
	msg := &netlink.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  msgtype,
			Flags: flags | syscall.NLM_F_REQUEST,
		},
		Data: data,
	}

	return nl.SendMessage(msg, sockflags, ack)
}

func (al *AuditNLSocket) Reply(sockflags int) ([]netlink.NetlinkMessage, error) {
	return al.RecvMessages(MAX_AUDIT_MESSAGE_LENGTH, sockflags)
}

func (al *AuditNLSocket) RequestWithReply(msgtype, flags uint16, data []byte) ([]netlink.NetlinkMessage, error) {
	err := al.Request(msgtype, flags, data, 0, false)
	if err != nil {
		return []netlink.NetlinkMessage{}, nil
	}

	for {
		msgList, err := al.Reply(0)
		if err != nil {
			return []netlink.NetlinkMessage{}, err
		}
		m := msgList[0]
		if m.Header.Type == msgtype {
			return msgList, nil
		}
	}
}

func (al *AuditNLSocket) GetStatus() (*AuditStatus, error) {
	msgList, err := al.RequestWithReply(AUDIT_GET, 0, nil)
	if err != nil {
		return nil, err
	}
	m := msgList[0]
	return AuditStatusfromWireFormat(m.Data), nil
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

func (al *AuditNLSocket) GetAuditEvents(enable bool) error {
	st,err := al.GetStatus()
	if err != nil {
		return err
	}

	if enable {
		st.Mask = AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID
		st.Enabled = 1
		st.Pid = uint32(os.Getpid())
	} else {
		if st.Pid == uint32(os.Getpid()) {
			st.Pid = 0
		}
	}

	err = al.SetStatus(st)
	if err != nil {
		return err
	}

	return nil
}


