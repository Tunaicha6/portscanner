package portscan

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidWorkers = errors.New("invalid workers count, must be greater than zero")
	ErrInvalidTimeout = errors.New("invalid timeout, must be greater than zero")

	ErrInvalidPort = errors.New("invalid port")
	ErrInvalidHost = errors.New("invalid host")
	ErrResolveHost = errors.New("failed to resolve host")

	ErrNoIPAddresses = errors.New("no IP addresses resolved")

	ErrNoValidIPs   = errors.New("no valid IP addresses")
	ErrNoValidPorts = errors.New("no valid ports")
)

type InputError struct {
	Field string
	Value string
	Err   error
}

func (e InputError) Error() string {
	return fmt.Sprintf("%s %q: %v", e.Field, e.Value, e.Err)
}

func (e InputError) Unwrap() error {
	return e.Err
}
