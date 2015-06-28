package netlink


import (
	"log"
	"syscall"
	"errors"
	"unsafe"
	"sync/atomic"
)


var (
	ErrInvalidSocket 	= errors.New("invalid socket")
)


type NetlinkSocket struct {
	sfd		int
	seq 	uint32
	lsa		syscall.SockaddrNetlink
}

type NetlinkMessage syscall.NetlinkMessage


func (msg *NetlinkMessage) toWireFormat() ([]byte) {
	if msg.Header.Len != syscall.NLMSG_HDRLEN + uint32(len(msg.Data)) {
		//return []byte("")
		msg.Header.Len = syscall.NLMSG_HDRLEN + uint32(len(msg.Data))
	}
	b := make([]byte, msg.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = msg.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = msg.Header.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = msg.Header.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = msg.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = msg.Header.Pid
	b = append(b[:16], msg.Data[:]...)
	return b
}


func (msg *NetlinkMessage) Show(prefix string) {
	log.Println(prefix, msg)
}


func OpenLink(NetlinkType int, group int, pid int) (*NetlinkSocket, error) {
	sfd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, NetlinkType)
	if err != nil {
		return nil, err
	}
	nl := &NetlinkSocket{
		sfd: sfd,
	}

	nl.lsa.Family = syscall.AF_NETLINK
	nl.lsa.Groups = uint32(group)
	nl.lsa.Pid = uint32(pid)

	nl.seq = 0

	//TODO: fcntl FD_CLOEXEC

	return nl, nil
}

func (nl *NetlinkSocket) CloseLink() (error) {
        if nl.sfd <= 0 {
                return ErrInvalidSocket
        }

        return syscall.Close(nl.sfd)
}


func (nl *NetlinkSocket) SendMessage(msg *NetlinkMessage, sockflags int, ack bool) error {
	if nl.sfd <= 0 {
		return ErrInvalidSocket
	}

	msg.Header.Len = syscall.NLMSG_HDRLEN + uint32(len(msg.Data))
	msg.Header.Seq = atomic.AddUint32(&nl.seq, 1)

	if ack == true {
		msg.Header.Flags = msg.Header.Flags | syscall.NLM_F_ACK
	}

	msg.Show(">>>")

	err := syscall.Sendto(nl.sfd, msg.toWireFormat(), sockflags, &nl.lsa)
	if err != nil {
		return err
	}

	if ack == true {
		msgList, err := nl.RecvMessages(0x1000, syscall.O_NONBLOCK)
		if err != nil || len(msgList) > 1 {
			return err
		}
	}

	return nil
}


func (nl *NetlinkSocket) RecvMessages(sz int, sockflags int) ([]NetlinkMessage, error) {
	if nl.sfd <= 0 {
		return nil,ErrInvalidSocket
	}

	buf := make([]byte, sz)

	rsz, _, err := syscall.Recvfrom(nl.sfd, buf, sockflags)
	if err != nil {
		return nil,err
	}

	if rsz < syscall.NLMSG_HDRLEN {
		return nil, syscall.EINVAL
	}


	msgList, err := syscall.ParseNetlinkMessage(buf[:rsz])
	if err != nil {
		return nil,err
	}

	ret := []NetlinkMessage{}

	for _,msg := range msgList {
		msg := NetlinkMessage(msg)
		msg.Show("<<<")
		ret = append(ret, msg)
	}

	return ret, nil
}