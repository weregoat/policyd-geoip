package main

import (
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"strings"
)

// Default facility for syslog output.
const DefaultFacility = syslog.LOG_MAIL

// Syslog is a struct holding the required properties for dialing syslog.
type Syslog struct {
	Facility     syslog.Priority
	Tag          string
	FacilityName string
	Debugging    bool
}

// Debug sends debug messages to syslog (if debugging is enabled).
func (l Syslog) Debug(message string) {
	if l.Debugging {
		Log(syslog.LOG_DEBUG, l.Facility, l.Tag, message)
	}
}

// Info sends info messages to syslog.
func (l Syslog) Info(message string) {
	Log(syslog.LOG_INFO, l.Facility, l.Tag, message)
}

// Notice sends notice messages to syslog.
func (l Syslog) Notice(message string) {
	Log(syslog.LOG_NOTICE, l.Facility, l.Tag, message)
}

// Warning sends warning level messages to syslog.
func (l Syslog) Warning(message string) {
	Log(syslog.LOG_WARNING, l.Facility, l.Tag, message)
}

// Err sends error messages to syslog.
func (l Syslog) Err(message string) {
	Log(syslog.LOG_ERR, l.Facility, l.Tag, message)
}

// Crit sends critical level messages to syslog.
func (l Syslog) Crit(message string) {
	Log(syslog.LOG_CRIT, l.Facility, l.Tag, message)
}

// Alert sends alert level messages to syslog.
func (l Syslog) Alert(message string) {
	Log(syslog.LOG_ALERT, l.Facility, l.Tag, message)
}

// Emerg sends emergency messages to syslog.
func (l Syslog) Emerg(message string) {
	Log(syslog.LOG_EMERG, l.Facility, l.Tag, message)
}

// Log is a wrapper for sending messages to syslog.
func Log(level syslog.Priority, facility syslog.Priority, tag, message string) {
	sysLog, err := syslog.Dial("", "", level|facility, tag)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
	}
	fmt.Fprint(sysLog, message)
}

// getPriorityName will convert a syslog.Priority to a string.
func getPriorityName(pri syslog.Priority) string {
	name := "unknown"
	switch pri {
	case syslog.LOG_INFO:
		name = "info"
	case syslog.LOG_MAIL:
		name = "mail"
	case syslog.LOG_DEBUG:
		name = "debug"
	case syslog.LOG_NOTICE:
		name = "notice"
	case syslog.LOG_CRIT:
		name = "crit"
	case syslog.LOG_EMERG:
		name = "emerg"
	case syslog.LOG_ALERT:
		name = "alert"
	case syslog.LOG_WARNING:
		name = "warning"
	case syslog.LOG_USER:
		name = "user"
	case syslog.LOG_DAEMON:
		name = "daemon"
	case syslog.LOG_AUTH:
		name = "auth"
	case syslog.LOG_AUTHPRIV:
		name = "authpriv"
	case syslog.LOG_LOCAL0:
		name = "local0"
	case syslog.LOG_LOCAL1:
		name = "local1"
	case syslog.LOG_LOCAL2:
		name = "local2"
	case syslog.LOG_LOCAL3:
		name = "local3"
	case syslog.LOG_LOCAL4:
		name = "local4"
	case syslog.LOG_LOCAL5:
		name = "local5"
	case syslog.LOG_LOCAL6:
		name = "local6"
	case syslog.LOG_LOCAL7:
		name = "local7"
	}
	return name
}

// getFacility converts between the name of a priority and syslog.Priority.
func getFacility(name string) (syslog.Priority, error) {
	var facility = DefaultFacility
	var err error
	if len(name) > 0 {
		switch strings.ToLower(strings.TrimSpace(name)) {
		// Not all the possible facility names are here; just the ones I think make sense.
		case "mail":
			facility = syslog.LOG_MAIL
		case "user":
			facility = syslog.LOG_USER
		case "daemon":
			facility = syslog.LOG_DAEMON
		case "auth":
			facility = syslog.LOG_AUTH
		case "authpriv":
			facility = syslog.LOG_AUTHPRIV
		case "local0":
			facility = syslog.LOG_LOCAL0
		case "local1":
			facility = syslog.LOG_LOCAL1
		case "local2":
			facility = syslog.LOG_LOCAL2
		case "local3":
			facility = syslog.LOG_LOCAL3
		case "local4":
			facility = syslog.LOG_LOCAL4
		case "local5":
			facility = syslog.LOG_LOCAL5
		case "local6":
			facility = syslog.LOG_LOCAL6
		case "local7":
			facility = syslog.LOG_LOCAL7
		default:
			err = errors.New(
				fmt.Sprintf("invalid syslog facility: %s", name),
			)

		}
	}
	return facility, err
}
