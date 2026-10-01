package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KairoteStudio/Kairc/internal/irc"
)

type client struct {
	id   uint64
	conn net.Conn
	host string

	send      chan string
	done      chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool
	ready     atomic.Bool

	// The fields below are owned exclusively by the hub goroutine.
	nick           string
	username       string
	realname       string
	capNegotiating bool
	channels       map[string]*channel
}

func newClient(id uint64, conn net.Conn, sendQueue int) *client {
	host := conn.RemoteAddr().String()
	if remoteHost, _, err := net.SplitHostPort(host); err == nil {
		host = remoteHost
	}
	return &client{
		id:       id,
		conn:     conn,
		host:     host,
		send:     make(chan string, sendQueue),
		done:     make(chan struct{}),
		channels: make(map[string]*channel),
	}
}

func (c *client) enqueue(line string) bool {
	if line == "" || c.closed.Load() {
		return false
	}
	select {
	case c.send <- line:
		return true
	default:
		c.close()
		return false
	}
}

func (c *client) close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.done)
		_ = c.conn.Close()
	})
}

func (c *client) prefix() string {
	return c.nick + "!" + c.username + "@" + c.host
}

func (c *client) writeLoop(ctx context.Context) {
	w := bufio.NewWriter(c.conn)
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case line := <-c.send:
			if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return
			}
			if _, err := io.WriteString(w, line); err != nil {
				c.close()
				return
			}
			if err := w.Flush(); err != nil {
				c.close()
				return
			}
		}
	}
}

type tokenBucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	now := time.Now()
	return &tokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: now}
}

func (b *tokenBucket) allow() bool {
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

var errLineTooLong = errors.New("IRC line too long")

func readLine(r *bufio.Reader) (string, error) {
	raw, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(raw) > irc.MaxPayloadBytes+2 {
		return "", errLineTooLong
	}
	if err != nil {
		return "", err
	}
	line := string(raw)
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if len(line) > irc.MaxPayloadBytes {
		return "", errLineTooLong
	}
	return line, nil
}
