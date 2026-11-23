package portscan

import (
	"net"
	"time"
)

type Config struct {
	Workers int
	Timeout time.Duration
}
type Scanner struct {
	config Config
}

type State string

const (
	StateOpen        State = "open"
	StateClosed      State = "closed"
	StateTimeout     State = "timeout"
	StateUnreachable State = "unreachable"
	StateCanceled    State = "canceled"
	StateError       State = "error"
)

type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}

type validAddress struct {
	IP    net.IP
	Port  uint16
	Hosts []string
}
type validIP struct {
	IP    net.IP
	Hosts []string
}
