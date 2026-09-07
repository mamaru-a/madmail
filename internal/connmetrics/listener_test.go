package connmetrics

import (
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestListenerCountsOpenConns(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()

	l := NewListener(inner, "test")

	const count = 3
	accepted := make(chan net.Conn, count)
	go func() {
		for i := 0; i < count; i++ {
			c, err := l.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()

	clients := make([]net.Conn, 0, count)
	for i := 0; i < count; i++ {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	server := make([]net.Conn, 0, count)
	for i := 0; i < count; i++ {
		c, ok := <-accepted
		if !ok {
			t.Fatal("Accept failed")
		}
		server = append(server, c)
	}

	if got := testutil.ToFloat64(activeConns.WithLabelValues("test")); got != count {
		t.Errorf("gauge after %d accepts = %v, want %d", count, got, count)
	}

	for _, c := range server {
		_ = c.Close()
		// Both go-imap and go-smtp close a connection twice on some paths;
		// the second Close must not decrement again.
		_ = c.Close()
	}

	if got := testutil.ToFloat64(activeConns.WithLabelValues("test")); got != 0 {
		t.Errorf("gauge after closing every conn = %v, want 0", got)
	}
}
