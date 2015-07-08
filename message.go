package netlink

import (
	"syscall"
	"unsafe"
)

type NetlinkMessage syscall.NetlinkMessage

func (msg *NetlinkMessage) toWireFormat() []byte {
	// Make sure Header.Len has the right value
	msg.Header.Len = syscall.NLMSG_HDRLEN + uint32(len(msg.Data))
	b := make([]byte, msg.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = msg.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = msg.Header.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = msg.Header.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = msg.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = msg.Header.Pid
	copy(b[16:], msg.Data[:])
	return b
}
