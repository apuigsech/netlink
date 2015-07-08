package audit

import "unsafe"

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

func AuditStatusfromWireFormat(data []byte) *AuditStatus {
	return (*AuditStatus)(unsafe.Pointer(&data[0:32][0]))
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
