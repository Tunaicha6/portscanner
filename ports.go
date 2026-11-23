package portscan

import (
	"fmt"
	"strconv"
	"strings"
)

func validatePorts(ports []int) ([]uint16, []InputError) {
	validPorts := make([]uint16, 0, len(ports))
	seen := make(map[int]struct{}, len(ports))
	inputErrors := make([]InputError, 0, len(ports))

	for _, val := range ports {
		_, exists := seen[val]
		if !exists {
			seen[val] = struct{}{}
			switch {
			case val <= 0:
				inputErrors = append(inputErrors, InputError{Field: "port", Value: strconv.Itoa(val), Err: ErrInvalidPort})
				continue
			case val > 65535:
				inputErrors = append(inputErrors, InputError{Field: "port", Value: strconv.Itoa(val), Err: ErrInvalidPort})
				continue
			default:
				validPorts = append(validPorts, uint16(val))
			}
		}
	}
	return validPorts, inputErrors
}
func ParsePorts(input string) ([]int, error) {
	input = strings.TrimSpace(input)

	if input == "" {
		return []int{}, nil
	}

	var ports []int
	seen := make(map[int]struct{})

	parts := strings.Split(input, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		if part == "" {
			return nil, fmt.Errorf("%w: empty port value", ErrInvalidPort)
		}

		rangeParts := strings.Split(part, "-")

		switch len(rangeParts) {
		case 1:
			port, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("%w: %q", ErrInvalidPort, part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("%w: %d", ErrInvalidPort, port)
			}

			if _, exists := seen[port]; !exists {
				ports = append(ports, port)
				seen[port] = struct{}{}
			}

		case 2:
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("%w: %q", ErrInvalidPort, part)
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("%w: %q", ErrInvalidPort, part)
			}

			if start < 1 || start > 65535 ||
				end < 1 || end > 65535 ||
				start > end {
				return nil, fmt.Errorf("%w: invalid range %q", ErrInvalidPort, part)
			}

			for port := start; port <= end; port++ {
				if _, exists := seen[port]; !exists {
					ports = append(ports, port)
					seen[port] = struct{}{}
				}
			}

		default:
			return nil, fmt.Errorf("%w: invalid range %q", ErrInvalidPort, part)
		}
	}

	return ports, nil
}
