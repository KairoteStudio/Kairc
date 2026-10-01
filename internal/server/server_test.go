package server

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

type memoryListener struct {
	connections chan net.Conn
	done        chan struct{}
	closeOnce   sync.Once
}

type memoryAddr string

func (a memoryAddr) Network() string { return "memory" }
func (a memoryAddr) String() string  { return string(a) }

func newMemoryListener() *memoryListener {
	return &memoryListener{connections: make(chan net.Conn), done: make(chan struct{})}
}

func (l *memoryListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memoryListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *memoryListener) Addr() net.Addr { return memoryAddr("kairc-test") }

func (l *memoryListener) Dial(t *testing.T) net.Conn {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	select {
	case l.connections <- serverConn:
		return clientConn
	case <-l.done:
		t.Fatal("dial on closed memory listener")
		return nil
	case <-time.After(2 * time.Second):
		t.Fatal("memory listener did not accept connection")
		return nil
	}
}

func startTestServer(t *testing.T) (*memoryListener, context.CancelFunc) {
	t.Helper()
	listener := newMemoryListener()
	cfg := DefaultConfig()
	cfg.Name = "irc.test"
	cfg.Network = "TestNet"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("server did not stop")
		}
	})
	return listener, cancel
}

func dialTestClient(t *testing.T, listener *memoryListener, nick string) *testClient {
	t.Helper()
	conn := listener.Dial(t)
	c := &testClient{conn: conn, reader: bufio.NewReader(conn)}
	t.Cleanup(func() { _ = conn.Close() })
	c.send(t, "CAP LS 302")
	c.readUntil(t, " CAP * LS :")
	c.send(t, "NICK "+nick)
	c.send(t, "USER "+strings.ToLower(nick)+" 0 * :"+nick+" Example")
	c.send(t, "CAP END")
	c.readUntil(t, " 001 "+nick+" ")
	c.readUntil(t, " 376 "+nick+" ")
	return c
}

func (c *testClient) send(t *testing.T, line string) {
	t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		t.Fatalf("send %q: %v", line, err)
	}
}

func (c *testClient) readUntil(t *testing.T, fragment string) string {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var seen strings.Builder
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			t.Fatalf("waiting for %q after receiving %q: %v", fragment, seen.String(), err)
		}
		seen.WriteString(line)
		if strings.Contains(line, fragment) {
			return line
		}
	}
}

func TestTwoClientsCanTalkInChannel(t *testing.T) {
	listener, _ := startTestServer(t)
	alice := dialTestClient(t, listener, "Alice")
	bob := dialTestClient(t, listener, "Bob")

	alice.send(t, "JOIN #lobby")
	alice.readUntil(t, ":Alice!alice@")
	alice.readUntil(t, " 366 Alice #lobby ")

	bob.send(t, "JOIN #lobby")
	bob.readUntil(t, " 366 Bob #lobby ")
	alice.readUntil(t, ":Bob!bob@")

	alice.send(t, "PRIVMSG #lobby :hello from Alice")
	line := bob.readUntil(t, " PRIVMSG #lobby :hello from Alice")
	if !strings.HasPrefix(line, ":Alice!alice@") {
		t.Fatalf("unexpected message prefix: %q", line)
	}

	bob.send(t, "NICK aLICE")
	bob.readUntil(t, " 433 Bob aLICE ")

	alice.send(t, "TOPIC #lobby :A small public room")
	alice.readUntil(t, " TOPIC #lobby :A small public room")

	alice.send(t, "WHO #lobby")
	alice.readUntil(t, " 352 Alice #lobby bob ")
	alice.readUntil(t, " 315 Alice #lobby ")

	alice.send(t, "KICK #lobby Bob :testing moderation")
	bob.readUntil(t, " KICK #lobby Bob :testing moderation")
}

func TestDirectMessageAndQuit(t *testing.T) {
	listener, _ := startTestServer(t)
	alice := dialTestClient(t, listener, "Alice")
	bob := dialTestClient(t, listener, "Bob")

	alice.send(t, "PRIVMSG Bob :private hello")
	bob.readUntil(t, " PRIVMSG Bob :private hello")

	alice.send(t, "JOIN #room")
	alice.readUntil(t, " 366 Alice #room ")
	bob.send(t, "JOIN #room")
	bob.readUntil(t, " 366 Bob #room ")
	alice.readUntil(t, ":Bob!bob@")

	bob.send(t, "QUIT :gone fishing")
	alice.readUntil(t, " QUIT :gone fishing")
}

func TestReadLineEnforcesWireLimit(t *testing.T) {
	valid := strings.Repeat("x", 510) + "\r\n"
	line, err := readLine(bufio.NewReaderSize(strings.NewReader(valid), ircReadBufferSize()))
	if err != nil || len(line) != 510 {
		t.Fatalf("valid line: len=%d err=%v", len(line), err)
	}

	tooLong := strings.Repeat("x", 511) + "\r\n"
	if _, err := readLine(bufio.NewReaderSize(strings.NewReader(tooLong), ircReadBufferSize())); err == nil {
		t.Fatal("readLine accepted a message larger than 512 wire bytes")
	}
}

func ircReadBufferSize() int { return 512 }
