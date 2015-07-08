package netlink

import (
	"errors"
	"sync"
	"syscall"
)

type NetlinkSocket struct {
	sfd int
	lsa syscall.SockaddrNetlink

	mu  sync.Mutex // protects seq
	seq uint32
}

func OpenLink(socktype int, group, pid uint32) (*NetlinkSocket, error) {
	sfd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, socktype)
	if err != nil {
		return nil, err
	}

	nl := &NetlinkSocket{
		sfd: sfd,
		lsa: syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
			Groups: group,
			Pid:    pid,
		},
		seq: 0,
	}

	return nl, nil
}

func (nl *NetlinkSocket) CloseLink() error {
	return syscall.Close(nl.sfd)
}

func (nl *NetlinkSocket) SendMessage(msg *NetlinkMessage, sockflags int, ack bool) error {
	msg.Header.Len = syscall.NLMSG_HDRLEN + uint32(len(msg.Data))
	msg.Header.Seq = nl.nextSeq()

	if ack {
		msg.Header.Flags = msg.Header.Flags | syscall.NLM_F_ACK
	}

	logf("sent: %+v\n", msg)

	err := syscall.Sendto(nl.sfd, msg.toWireFormat(), sockflags, &nl.lsa)
	if err != nil {
		return err
	}

	if ack {
		msgList, err := nl.RecvMessages(syscall.Getpagesize(), syscall.O_NONBLOCK)
		if err != nil || len(msgList) > 1 {
			return errors.New("cannot receive messages")
		}
	}

	return nil
}

func (nl *NetlinkSocket) nextSeq() uint32 {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	nl.seq++
	return nl.seq
}

func (nl *NetlinkSocket) RecvMessages(sz, sockflags int) ([]NetlinkMessage, error) {
	buf := make([]byte, sz)

	rsz, _, err := syscall.Recvfrom(nl.sfd, buf, sockflags)
	if err != nil {
		return nil, err
	}

	if rsz < syscall.NLMSG_HDRLEN {
		return nil, syscall.EINVAL
	}

	msgList, err := syscall.ParseNetlinkMessage(buf[:rsz])
	if err != nil {
		return nil, err
	}

	ret := []NetlinkMessage{}

	for _, msg := range msgList {
		msg := NetlinkMessage(msg)
		logf("received: %+v\n", msg)
		ret = append(ret, msg)
	}

	return ret, nil
}

func (nl *NetlinkSocket) RecvMessagesRaw(sz, sockflags int) ([]byte, error) {
	buf := make([]byte, sz)

	rsz, _, err := syscall.Recvfrom(nl.sfd, buf, sockflags)
	if err != nil {
		return nil, err
	}

	return buf[:rsz], nil
}
