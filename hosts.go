package portscan

import (
	"context"
	"fmt"
	"net"
	"strings"
)

func validateHosts(hosts []string) ([]string, []InputError) {
	validHosts := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	inputErrors := make([]InputError, 0, len(hosts))

	for _, val := range hosts {
		val = strings.TrimSpace(val)
		if val == "" {
			inputErrors = append(inputErrors, InputError{Field: "host", Value: val, Err: ErrInvalidHost})
			continue
		}
		if _, exists := seen[val]; exists {
			continue
		}
		seen[val] = struct{}{}
		validHosts = append(validHosts, val)
	}
	return validHosts, inputErrors
}
func resolveHosts(ctx context.Context, hosts []string) ([]validIP, []InputError, error) {
	inputErrors := make([]InputError, 0, len(hosts))
	validIPs := make([]validIP, 0, len(hosts))
	seen := make(map[string]int, len(hosts))
	for _, host := range hosts {

		if err := ctx.Err(); err != nil {
			return validIPs, inputErrors, err
		}

		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			if ctx.Err() != nil {
				return validIPs, inputErrors, ctx.Err()
			}
			inputErrors = append(inputErrors, InputError{
				Field: "host",
				Value: host,
				Err:   fmt.Errorf("%w: %w", ErrResolveHost, err),
			})
			continue
		}

		if len(addrs) == 0 {
			inputErrors = append(inputErrors, InputError{Field: "host", Value: host, Err: ErrNoIPAddresses})
			continue
		}
		seenForHost := make(map[string]struct{}, len(addrs))
		for _, addr := range addrs {
			ip := addr.IP.String()

			if _, exists := seenForHost[ip]; exists {
				continue
			}
			seenForHost[ip] = struct{}{}

			idx, exists := seen[ip]
			if !exists {
				validIPs = append(validIPs, validIP{IP: addr.IP, Hosts: []string{host}})
				seen[ip] = len(validIPs) - 1
				continue
			}
			validIPs[idx].Hosts = append(validIPs[idx].Hosts, host)
		}

	}
	if err := ctx.Err(); err != nil {
		return validIPs, inputErrors, err
	}
	return validIPs, inputErrors, nil
}
