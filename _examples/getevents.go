package main

import (
	"log"
	"os"
	"time"

	"github.com/apuigsech/netlink"
	"github.com/apuigsech/netlink/protocols/audit"
)

func EventCallback(ae *audit.AuditEvent, ce chan error, args ...interface{}) {
	log.Println(ae)
}


func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	netlink.Logger = logger

	al,_ := audit.OpenLink(0, 0)

	al.StartEventMonitor(EventCallback, nil)

	time.Sleep(3600 * time.Second)
}