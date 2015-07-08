package netlink

import "log"

// Logger is the logger used to register warnings and info messages. If it is nil,
// no messages will be logged.
var Logger *log.Logger

func logf(format string, args ...interface{}) {
	if Logger == nil {
		return
	}
	Logger.Printf(format, args...)
}
