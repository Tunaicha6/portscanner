package portscan

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const channelBufferSize = 50

func New(config Config) (*Scanner, error) {
	if config.Workers < 1 {
		return nil, ErrInvalidWorkers
	}
	if config.Timeout <= 0 {
		return nil, ErrInvalidTimeout
	}

	return &Scanner{config: config}, nil
}
func (s *Scanner) Scan(
	ctx context.Context,
	hosts []string,
	ports []int,
) ([]Result, []InputError, error) {
	if s == nil {
		return nil, nil, errors.New("scanner cannot be nil")
	}
	if ctx == nil {
		return nil, nil, errors.New("context cannot be nil")
	}

	hosts = append([]string(nil), hosts...)
	ports = append([]int(nil), ports...)

	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	inputErrors := make([]InputError, 0, len(ports)+len(hosts))
	var wg sync.WaitGroup

	validPorts, portsErr := validatePorts(ports)
	inputErrors = append(inputErrors, portsErr...)

	validHosts, hostsErr := validateHosts(hosts)
	inputErrors = append(inputErrors, hostsErr...)

	validIPs, ipsErr, err := resolveHosts(ctx, validHosts)
	if err != nil {
		return nil, inputErrors, err
	}
	inputErrors = append(inputErrors, ipsErr...)

	if err = ctx.Err(); err != nil {
		return nil, inputErrors, err
	}

	if len(validIPs) == 0 {
		return nil, inputErrors, ErrNoValidIPs
	}

	if len(validPorts) == 0 {
		return nil, inputErrors, ErrNoValidPorts
	}

	scanResults := make([]Result, 0)
	jobs := make(chan validAddress, channelBufferSize)
	results := make(chan Result, channelBufferSize)

	for range s.config.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, results)
		}()
	}

	go produceJobs(ctx, validIPs, validPorts, jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	for val := range results {
		scanResults = append(scanResults, val)
	}

	sort.Slice(scanResults, func(i, j int) bool {
		if scanResults[i].Host != scanResults[j].Host {
			return scanResults[i].Host < scanResults[j].Host
		}

		if scanResults[i].IP.String() != scanResults[j].IP.String() {
			return scanResults[i].IP.String() < scanResults[j].IP.String()
		}

		return scanResults[i].Port < scanResults[j].Port
	})

	return scanResults, inputErrors, ctx.Err()
}
func (s *Scanner) worker(
	ctx context.Context,
	jobs <-chan validAddress,
	results chan<- Result,
) {
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return

		case job, ok := <-jobs:
			if !ok {
				return
			}

			if ctx.Err() != nil {
				return
			}

			address := net.JoinHostPort(
				job.IP.String(),
				strconv.Itoa(int(job.Port)),
			)

			dialer := net.Dialer{
				Timeout: s.config.Timeout,
			}

			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", address)
			duration := time.Since(start)

			if conn != nil {
				_ = conn.Close()
			}

			for _, host := range job.Hosts {
				result := Result{
					Host:     host,
					IP:       append(net.IP(nil), job.IP...),
					Port:     job.Port,
					State:    classifyState(ctx, err),
					Duration: duration,
					Err:      err,
				}

				select {
				case <-ctx.Done():
					return
				case results <- result:
				}
			}
		}
	}
}

func produceJobs(
	ctx context.Context,
	validIPs []validIP,
	validPorts []uint16,
	jobs chan<- validAddress,
) {
	defer close(jobs)

	for _, ip := range validIPs {
		for _, port := range validPorts {
			if ctx.Err() != nil {
				return
			}

			job := validAddress{
				IP:    ip.IP,
				Port:  port,
				Hosts: ip.Hosts,
			}

			select {
			case <-ctx.Done():
				return
			case jobs <- job:
			}
		}
	}
}
func classifyState(ctx context.Context, err error) State {
	var netErr net.Error

	if err == nil {
		return StateOpen
	}

	switch {
	case errors.Is(err, context.Canceled):
		return StateCanceled

	case errors.Is(err, context.DeadlineExceeded):
		return StateTimeout

	case errors.As(err, &netErr) && netErr.Timeout():
		return StateTimeout

	case errors.Is(err, syscall.ECONNREFUSED):
		return StateClosed

	case errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EHOSTUNREACH):
		return StateUnreachable

	default:
		if ctx.Err() != nil {
			return StateCanceled
		}

		return StateError
	}
}
