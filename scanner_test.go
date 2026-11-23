package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func newTestScanner(t *testing.T) *Scanner {
	t.Helper()

	scanner, err := New(Config{
		Workers: 4,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return scanner
}

func startTestServer(t *testing.T) (string, uint16) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	return "127.0.0.1", port
}

func TestScanOpenPort(t *testing.T) {
	scanner := newTestScanner(t)
	host, port := startTestServer(t)

	results, inputErrors, err := scanner.Scan(
		context.Background(),
		[]string{host},
		[]int{int(port)},
	)

	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(inputErrors) != 0 {
		t.Fatalf("unexpected input errors: %v", inputErrors)
	}
	if len(results) != 1 {
		t.Fatalf("results count = %d, want 1", len(results))
	}
	if results[0].State != StateOpen {
		t.Errorf("state = %q, want %q", results[0].State, StateOpen)
	}
	if results[0].Err != nil {
		t.Errorf("unexpected result error: %v", results[0].Err)
	}
}

func TestScanClosedPort(t *testing.T) {
	scanner := newTestScanner(t)

	// Получаем свободный порт, после чего закрываем listener.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}

	results, inputErrors, err := scanner.Scan(
		context.Background(),
		[]string{"127.0.0.1"},
		[]int{port},
	)

	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(inputErrors) != 0 {
		t.Fatalf("unexpected input errors: %v", inputErrors)
	}
	if len(results) != 1 {
		t.Fatalf("results count = %d, want 1", len(results))
	}
	if results[0].State != StateClosed {
		t.Errorf("state = %q, want %q", results[0].State, StateClosed)
	}
}

func TestScanInvalidInput(t *testing.T) {
	scanner := newTestScanner(t)

	results, inputErrors, err := scanner.Scan(
		context.Background(),
		[]string{"", "   "},
		[]int{0, -1, 65536},
	)

	if err != ErrNoValidIPs {
		t.Fatalf("Scan() error = %v, want %v", err, ErrNoValidIPs)
	}
	if len(results) != 0 {
		t.Errorf("results count = %d, want 0", len(results))
	}
	if len(inputErrors) != 5 {
		t.Errorf("input errors count = %d, want 5", len(inputErrors))
	}

	for _, inputErr := range inputErrors {
		if inputErr.Err == nil {
			t.Errorf("input error for %q has nil Err", inputErr.Value)
		}
	}
}

func TestScanCanceledContext(t *testing.T) {
	scanner := newTestScanner(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, _, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]int{80},
	)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan() error = %v, want context.Canceled", err)
	}
	if len(results) != 0 {
		t.Errorf("results count = %d, want 0", len(results))
	}
}

func TestScanCancelDuringExecution(t *testing.T) {
	scanner, err := New(Config{
		Workers: 1,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)

	go func() {
		_, _, err := scanner.Scan(
			ctx,
			[]string{"127.0.0.1"},
			ports,
		)
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Scan() error = %v, want context.Canceled", err)
		}

	case <-time.After(2 * time.Second):
		t.Fatal("Scan() did not stop after context cancellation")
	}
}

func TestScannerReuse(t *testing.T) {
	scanner := newTestScanner(t)
	host, port := startTestServer(t)

	for i := 0; i < 2; i++ {
		results, inputErrors, err := scanner.Scan(
			context.Background(),
			[]string{host},
			[]int{int(port)},
		)

		if err != nil {
			t.Fatalf("Scan() iteration %d error = %v", i, err)
		}
		if len(inputErrors) != 0 {
			t.Fatalf("iteration %d: unexpected input errors: %v", i, inputErrors)
		}
		if len(results) != 1 {
			t.Fatalf("iteration %d: results count = %d, want 1", i, len(results))
		}
		if results[0].State != StateOpen {
			t.Errorf("iteration %d: state = %q, want %q", i, results[0].State, StateOpen)
		}
	}
}
func TestScannerConcurrentUse(t *testing.T) {
	scanner := newTestScanner(t)
	host, port := startTestServer(t)

	const scanCount = 2

	start := make(chan struct{})
	errCh := make(chan error, scanCount)

	for i := 0; i < scanCount; i++ {
		go func() {
			<-start

			results, inputErrors, err := scanner.Scan(
				context.Background(),
				[]string{host},
				[]int{int(port)},
			)

			if err != nil {
				errCh <- err
				return
			}

			if len(inputErrors) != 0 {
				errCh <- errors.New("unexpected input errors")
				return
			}

			if len(results) != 1 {
				errCh <- fmt.Errorf(
					"results count = %d, want 1",
					len(results),
				)
				return
			}

			if results[0].State != StateOpen {
				errCh <- fmt.Errorf(
					"state = %q, want %q",
					results[0].State,
					StateOpen,
				)
				return
			}

			errCh <- nil
		}()
	}

	close(start)

	for i := 0; i < scanCount; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent Scan() error: %v", err)
		}
	}
}
