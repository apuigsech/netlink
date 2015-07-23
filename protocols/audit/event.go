package audit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"errors"
//	"encoding/hex"
)

type EventCallback func(*AuditEvent, chan error, ...interface{})

type AuditEvent struct {
	Raw					string

	Args 				map[int]interface{}			// a? - numeric, the arguments to a syscall.
	Acct 				interface{}					// acct - encoded, a user's account name.
	Addr 				interface{}					// addr - the remote address that the user is connecting from.
	Arch 				*int 						// arch - numeric, the elf architecture flags.
	Argc 				*int 						// argc - numeric, the number of arguments to an execve syscall.
	Audit_backlog_limit	*int 						// audit_backlog_limit - numeric, audit system's backlog queue size.
	Audit_enabled 		*int 						// audit_enabled - numeric, audit systems's enable/disable status.
	Audit_failure 		*int 						// audit_failure - numeric, audit system's failure mode.
	Auid 				*int 						// auid - numeric, login user id.
	Banners 			*string 					// banners - alphanumeric, banners used on printed page.
	Capability 			*int  						// capability - numeric, posix capabilities.
	Cap_fi 				*int 						// cap_fi - numeric, file inherited capability map.
	Cap_fp 				*int 						// cap_fp - numeric, file permitted capability map.
	Cap_fver 			*int 						// cap_fver - numeric, file system capabilities version number.
	Cap_pe 				*int 						// cap_pe - numeric, process effective capability map.
	Cap_pi 				*int 						// cap_pi - numeric, process inherited capability map.
	Cap_pp 				*int 						// cap_pp - numeric, process permitted capability map.
	Cipher 				*string 					// cipher - alphanumeric, name of crypto cipher selected.
	Code 				*int 						// code - numeric, seccomp action code.
	Comm 				*string						// comm - encoded, command line program name.
	Cmd 				*interface{} 				// cmd - encoded, command being executed.
	Cwd 				*interface{} 				// cwd - encoded, the current working directory.
	Data 				*interface{} 				// data - encoded, TTY text
	Default_context		*string 					// default-context - alphanumeric, default MAC context.
	Dev 				*int 						// dev - numeric, in path records, major and minor for device. in avc records, device name as found in /dev.
	Device 				*interface{} 				// device - encoded, device name.
	Dir 				*interface{} 				// dir - encoded, directory name.
	Direction 			*string 					// direction - alphanumeric, direction of crypto operation.
	Egid 				*int 						// egid - numeric, effective group id.
	Enforcing 			*int 						// enforcing - numeric, new MAC enforcement status.
	Entries 			*int 						// entries - numeric, number of entries in the netfilter table
	Euid 				*int 						// euid - numeric, effective user id
	Exe 				*string 					// exe - encoded, executable name
	Exit 				*int 						// exit - numeric, syscall exit code
	Family 				*int 						// family - numeric, netfilter protocol.
	Fd 					*int 						// fd - numeric, file descriptor number.
	File 				*interface{}				// file - encoded, file name.
	Flags 				*int 						// flags - numeric, mmap syscall flags.
	Fe 					*int 						// fe - numeric, file assigned effective capability map.
	Fi 					*int 						// fi - numeric, file assigned inherited capability map.
	Fp 					*int 						// fp - numeric, file assigned permitted capability map.
													//fp - alphanumeric, crypto key finger print
	Format 				*string 					// format - alphanumeric, audit log's format.
	Fsgid 				*int 						// fsgid - numeric, file system group id.
	Fsuid 				*int 						// fsuid - numeric, file system user id.
	Fver 				*int 						// fver - numeric, file system capabilities version number.
	Gid 				*int 						// gid - numeric, group id.
	Hostname 			*string 					// hostname - alphanumeric, the hostname that the user is connecting from.
	Icmp_type 			*int 						// icmp_type - numeric, type of icmp message.
	Id 					*int 						// id - numeric, during account changes, the user id of the account.
	Igid 				*int 						// igid - numeric, ipc object's group id.
	Img_ctx 			*string 					// img-ctx - alphanumeric, the vm's disk image context string.
	Ip 					*string 					// ip - alphanumeric, network address of a printer.
	Inode 				*int 						// inode - numeric, inode number.
	Inode_gid 			*int 						// inode_gid - numeric, group id of the inode's owner.
	Inode_uid 			*int 						// inode_uid - numeric, user id of the inode's owner.
	Item 				*int 						// item - numeric, which item is being recorded.
	Items 				*int 						// items - numeric, the number of path records in the event.
	Iuid 				*int 						// iuid - numeric, ipc object's user id.
	Kernel 				*string 					// kernel - alphanumeric, kernel's version number.
	Key 				*string 					// key - encoded, key assigned from triggered audit rule.
	Kind 				*string 					// kind - alphabet, server or client in crypto operation.
	Ksize 				*int 						// ksize - numeric, key size for crypto operation.
	Laddr 				*string 					// laddr - alphanumeric, local network address used in crypto session.
	Lport 				*string 					// lport - alphanumeric, local network port used in crypto session.
	List 				*int 						// list - numeric, the audit system's filter list number.
	Mac 				*string 					// mac - alphanumeric, crypto MAC algorithm selected.
	Mode 				*int 						// mode - numeric, mode flags on a file.
	Model 				*string 					// model - alphanumeric, security model being used for virt.
	Msg 				*string 					// msg - alphanumeric, the payload of the audit record.
	Nargs 				*int 						// nargs - numeric, the number of arguments to a socket call.
	Name 				*interface{} 				// name - encoded, file name in avcs.
	Nametype 			*string 					// nametype - alphabet, kind of file operation being referenced.
	Net 				*string 					// net - alphanumeric, network MAC address.
	New_disk 			*interface{} 				// new-disk - encoded, disk being added to vm.
	New_fs 				*interface{} 				// new-fs - encoded, file system being added to vm.
	New_gid				*int 						// new_gid - numeric, new group id being assigned.
	New_level			*string 					// new-level - alphanumeric, new run level.
	New_pe 				*int 						// new_pe - numeric, new process effective capability map.
	New_pi 				*int 						// new_pi - numeric, new process inherited capability map.
	New_pp 				*int 						// new_pp - numeric, new process permitted capability map.
	New_rng				*interface{} 				// new-rng - encoded, device name of rng being added from a vm.
	Obj 				*string 					// obj - alphanumeric, lspp object context string.
	Obj_gid 			*int 						// obj_gid - numeric, group id of object.
	Obj_uid 			*int 						// obj_uid - numeric, user id of object.
	Oflag 				*int 						// oflag - numeric, open syscall flags.
	Ogid 				*int  						// ogid - numeric, file owner group id.
	Old 				*int 						// old - numeric, old audit_enabled, audit_backlog, or audit_failure value.
	Old_disk 			*interface{} 				// old-disk - encoded, disk being removed from vm.
	Old_enforcing 		*int 						// old_enforcing - numeric, old MAC enforcement status.
	Old_fs 				*interface{} 				// old-fs - encode, file system being removed from vm.
	Old_level			*string 					// old-level - alphanumeric, old run level.
	Old_pe 				*int 						// old_pe - numeric, old process effective capability map.
	Old_pi 				*int 						// old_pi - numeric, old process inherited capability map.
	Old_pp 				*int 						// old_pp - numeric, old process permitted capability map.
	Old_prom 			int 						// old_prom - numeric, network promiscuity flag.
	Old_rng 			*interface{} 				// old-rng - encoded, device name of rng being removed from a vm.
	Op 					*string 					// op - alphanumeric, the operation being performed that is audited.
	Oauid 				*int 						// oauid - numeric, process login user id.
	Ocomm 				*interface{} 				// ocomm - encoded, object's command line name.
	Opid 				*int 						// opid - numeric, object's process id.
	Oses 				*int 						// oses - numeric, object's session id.
	Ouid 				*int 						// ouid - numeric, file owner user id.
	Parent 				*int 						// parent - numeric, the inode number of the parent file.
	Path 				*interface{} 				// path - iencoded, file system path name.
	Per 				*int 						// per - numeric, linux personality.
	Perm 				*int 						// perm - numeric, the file permission being used.
	Perm_mask 			*int 						// perm_mask - numeric, file permission mask that triggered a watch event.
	Pid 				*int 						// pid - numeric, process id.
	Ppid 				*int 						//
	Printer 			*interface{} 				// printer - encoded, printer name.
	Prom 				*int 						// prom - numeric, network promiscuity flag.
	Proctitle 			*interface{} 				// proctitle - encoded, process title and command line parameters
	Proto 				*int 						// proto - numeric, network protocol
	Qbytes 				*int 						// qbytes - numeric, ipc objects quantity of bytes
	Range 				*string 					// range - alphanumeric, user's SE Linux range
	Rdev 				*int 						// rdev - numeric, the device identifier (special files only)
	Reason 				*string 					// reason - alphanumeric, a text string denoting a reason for the action
	Res 				*string 					// res - alphanumeric, result of the audited operation (success/fail)
	Result 				*string 					// result - alphanumeric, result of the audited operation (success/fail)
	Role 				*string 					// role - alphanumeric, user's SE linux role
	Rport 				*int 						// rport - numeric, remote port number
	Saddr 				*interface{} 				// saddr - encoded, struct socket address structure
    Sauid 				*int  						// sauid - numeric, sending login user id
	Scontext 			*string 					// scontext - alphanumeric, the subject's context string
	Selected_context 	*string 					// selected-context - alphanumeric, new MAC context assigned to session
	Seuser 				*string 					// seuser - alphanumeric, user's SE Linux user acct
	Ses 				*int 						// ses - numeric, login session id
	Sgid 				*int 						// sgid - numeric, set group id
	Sig 				*int 						// sig - numeric, signal number
	Sigev_signo 		*int 						// sigev_signo - numeric, signal number
	Spid 				*int 						// spid - numeric, sending process id
	Subj 				*string 					// subj - alphanumeric, lspp subject's context string
	Success 			*string 					// success - alphanumeric, whether the syscall was successful or not
    Suid 				*int 						// suid - numeric, sending user id
	Syscall 			*int 						// syscall - numeric, the syscall number in effect when the event occurred
	Table 				*string 					// table - alphanumeric, netfilter table name
	Tclass 				*string 					// tclass - alphanumeric, target's object classification
	Tcontext 			*string 					// tcontext - alphanumeric, the target's or object's context string
	Terminal 			*string 					// terminal - alphanumeric, terminal name the user is running programs on
	Tty 				*string 					// tty - alphanumeric, tty interface that the user is running programs on
	Type 				*string 					// type - alphanumeric, the audit record's type
	Uid 				*int 						// uid - numeric, user id
	Uri 				*string 					// uri - alphanumeric, URI pointing to a printer
	User 				*string 					// user - alphanumeric, account the user claims to be prior to authentication
	Uuid 				*string 					// uuid - alphanumeric, a UUID
	Ver 				*int 						// ver - numeric, audit daemon's version number
	Virt 				*string 					// virt - alphanumeric, kind of virtualization being referenced
	Vm 					*interface{}				// vm - encoded, virtual machine name
	Vm_ctc 				*string 					// vm-ctx - alphanumeric, the vm's context string
	Watch 				*interface{}				// watch - encoded, file name in a watch record

	Timestamp			float64
	Serial				int
}

func ParseInt(value string, base int) (*int) {
	v,err := strconv.ParseInt(value, base, 32)
	ret := int(v)
	if err != nil {
		//fmt.Println("Unexpected VALUE", value, err)
		return nil
	}
	return &ret
}

func ParseString(value string) (*string) {
	ret := value
	return &ret
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
	
//	info := make(map[string]interface{})
	args := make(map[int]interface{})
	event := &AuditEvent{
		Raw:		data[3],
		Args:		args,		
		Timestamp:	timestamp,
		Serial:		int(serial),
	}

	for _, e := range strings.Split(data[3], " ") {
		a := strings.Split(e, "=")
		if len(a) == 2 {
			key := a[0]
			value := a[1]
			re := regexp.MustCompile(`^a(\d+)$`)
			switch key {
			case re.FindString(key):
				data := re.FindStringSubmatch(key)
				if len(data) == 2 {
					i,err := strconv.ParseInt(data[1], 10, 32)
					if err == nil {
						event.Args[int(i)] = a[1]
					}
				}		
			case "arch":
				event.Arch = ParseInt(value, 16)
			case "auid":
				event.Auid = ParseInt(value, 10)
			case "comm":
				event.Comm = ParseString(value)
			case "egid":
				event.Egid = ParseInt(value, 10)
			case "euid":
				event.Euid = ParseInt(value, 10)
			case "exe":
				event.Exe = ParseString(value)
			case "exit":
				event.Exit = ParseInt(value, 10)
			case "fsgid":
				event.Fsgid = ParseInt(value, 10)
			case "fsuid":
				event.Fsuid = ParseInt(value, 10)
			case "gid":
				event.Gid = ParseInt(value, 10)
			case "items":
				event.Items = ParseInt(value, 10)
			case "key":
				event.Key = ParseString(value)
			case "pid":
				event.Pid = ParseInt(value, 10)
			case "ppid":
				event.Ppid = ParseInt(value, 10)
			case "ses":
				event.Ses = ParseInt(value, 10)
			case "sgid":
				event.Sgid = ParseInt(value, 10)
			case "success":
				event.Success = ParseString(value)
			case "syscall":
				event.Syscall = ParseInt(value, 10)
			case "suid":
				event.Suid = ParseInt(value, 10)
			case "tty":
				event.Tty = ParseString(value)
			case "uid":
				event.Uid = ParseInt(value, 10)
			default:
				fmt.Println("Unsupported KEY", key, value)
			}

		/*
			re := regexp.MustCompile(`^a(\d+)$`)
			key := a[0]
			var value interface{}
			switch key {
			case re.FindString(key):
				data := re.FindStringSubmatch(key)
				if len(data) == 2 {
					i,err := strconv.ParseInt(data[1], 10, 32)
					if err == nil {
						event.Args[int(i)] = a[1]
					}
				}
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
			*/
		}
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
