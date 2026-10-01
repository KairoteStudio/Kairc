// Package server implements a small, single-node IRC server.
package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KairoteStudio/Kairc/internal/irc"
)

// Server accepts IRC connections and dispatches every state change through one
// hub goroutine. The actor-like ownership keeps room and nickname state race-free.
type Server struct {
	cfg    Config
	log    *slog.Logger
	hub    *hub
	active atomic.Int64
	nextID atomic.Uint64
	wg     sync.WaitGroup
}

func New(cfg Config, logger *slog.Logger) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, log: logger, hub: newHub(cfg, logger)}, nil
}

// Serve runs until ctx is cancelled or the listener fails permanently.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go s.hub.run(ctx)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var delay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if delay > time.Second {
					delay = time.Second
				}
				s.log.Warn("temporary accept error", "error", err, "retry_in", delay)
				select {
				case <-ctx.Done():
					break
				case <-time.After(delay):
					continue
				}
			}
			cancel()
			<-s.hub.done
			s.wg.Wait()
			return fmt.Errorf("accept IRC connection: %w", err)
		}
		delay = 0

		if s.active.Add(1) > int64(s.cfg.MaxClients) {
			s.active.Add(-1)
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write([]byte("ERROR :Server is full\r\n"))
			_ = conn.Close()
			continue
		}

		c := newClient(s.nextID.Add(1), conn, s.cfg.SendQueue)
		s.wg.Add(1)
		go s.serveClient(ctx, c)
	}

	cancel()
	<-s.hub.done
	s.wg.Wait()
	return nil
}

func (s *Server) serveClient(ctx context.Context, c *client) {
	defer s.wg.Done()
	defer s.active.Add(-1)
	defer c.close()

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writeLoop(ctx)
	}()

	select {
	case s.hub.register <- c:
	case <-ctx.Done():
		return
	}

	_ = c.conn.SetReadDeadline(time.Now().Add(s.cfg.RegistrationTimeout))
	reader := bufio.NewReaderSize(c.conn, irc.MaxPayloadBytes+2)
	limiter := newTokenBucket(s.cfg.MessagesPerSecond, s.cfg.MessageBurst)
	reason := "Connection closed"

	for {
		line, err := readLine(reader)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				reason = "Line too long"
			}
			break
		}
		if !limiter.allow() {
			reason = "Excess flood"
			break
		}
		msg, err := irc.Parse(line)
		if err != nil {
			continue
		}
		select {
		case s.hub.incoming <- inbound{client: c, message: msg}:
		case <-ctx.Done():
			return
		case <-c.done:
			return
		}

		if c.ready.Load() {
			_ = c.conn.SetReadDeadline(time.Time{})
		}
	}

	select {
	case s.hub.unregister <- departure{client: c, reason: reason}:
	case <-ctx.Done():
	}
	c.close()
	<-writerDone
}
