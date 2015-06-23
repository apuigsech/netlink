package netlink


import (
	"log"
	"syscall"
	"errors"
	"unsafe"
	"sync/atomic"
)


var (
	ErrInvalidSocket = errors.New("invalid socket")
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


func (msg *NetlinkMessage) Show() {
	log.Println(msg)
	//log.Println(msg.toWireFormat())
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

	if err := syscall.Bind(sfd, &nl.lsa); err != nil {
		syscall.Close(sfd)
		return nil, err
	}
	return nl, nil
}

func (nl *NetlinkSocket) CloseLink() (error) {
        if nl.sfd <= 0 {
                return ErrInvalidSocket
        }

        return syscall.Close(nl.sfd)
}


func (nl *NetlinkSocket) NewNetlinkMessage(msgtype int, flags int, data []byte) (*NetlinkMessage) {
	msg := &NetlinkMessage{}
	msg.Header.Len = syscall.NLMSG_HDRLEN + uint32(len(data))
	msg.Header.Type = uint16(msgtype)
	msg.Header.Flags = uint16(flags)
	msg.Header.Seq = atomic.AddUint32(&nl.seq, 1)
	msg.Header.Pid = 0
	msg.Data = data
	msg.Show()
	return msg
}


func (nl *NetlinkSocket) SendMessage(msg *NetlinkMessage, flags int) error {
	if nl.sfd <= 0 {
		return ErrInvalidSocket
	}

	return syscall.Sendto(nl.sfd, msg.toWireFormat(), flags, &nl.lsa)
}


func (nl *NetlinkSocket) RecvMessages(sz int, flags int) ([]NetlinkMessage, error) {
	if nl.sfd <= 0 {
		return nil,ErrInvalidSocket
	}

	buf := make([]byte, sz)

	rsz, _, err := syscall.Recvfrom(nl.sfd, buf, flags)
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
		ret = append(ret, NetlinkMessage(msg))
	}

	return ret, nil
}