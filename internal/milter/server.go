package milter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
)

const commandDatabaseTimeout = 15 * time.Second
const defaultMilterProgressInterval = 30 * time.Second
const initialAcceptRetryDelay = 5 * time.Millisecond
const maximumAcceptRetryDelay = time.Second
const commandReplySMTPTimeout = 15 * time.Second

var ErrInternalTokenGeneration = errors.New("cannot generate internal reply token")

type Server struct {
	log                *slog.Logger
	sessionSlots       chan struct{}
	maxConnections     int
	includeConnections bool
	allowedPeerIPs     []netip.Prefix
	database           *sqlitedb.Store
	wg                 sync.WaitGroup
	closeOnce          sync.Once
	closeErr           error
	startupErr         error
	sessions           *sessionDependencies
	maintenance        *maintenanceService
}

// NewServer assembles a Milter server without opening its listener. Callers
// must check StartupError before serving and call Close after Serve returns.
func NewServer(cfg config.Config, analyzer Analyzer, log *slog.Logger) *Server {
	runtime := buildRuntime(cfg, analyzer, log)
	return &Server{
		log: log, sessionSlots: make(chan struct{}, cfg.Milter.MaxConnections),
		maxConnections: cfg.Milter.MaxConnections, includeConnections: cfg.Logging.IncludeConnections,
		allowedPeerIPs: peerPrefixes(cfg.Milter.AllowedPeerIPs), database: runtime.database,
		startupErr: runtime.err, sessions: runtime.sessions, maintenance: runtime.maintenance,
	}
}

// Close releases persistent database resources. It may be called concurrently
// or more than once, but only after Serve has returned and command processing
// has stopped.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.database == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), commandDatabaseTimeout)
		defer cancel()
		if _, err := s.database.CheckpointPassive(ctx); err != nil && s.log != nil {
			s.log.Warn("final SQLite WAL checkpoint failed", "error", err)
		}
		s.closeErr = s.database.Close()
	})
	return s.closeErr
}

// StartupError reports persistent state that could not be loaded safely.
func (s *Server) StartupError() error { return s.startupErr }

// Serve performs startup maintenance, runs periodic cleanup, accepts bounded
// Milter connections, and waits for active sessions before returning.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.startupErr != nil {
		return s.startupErr
	}
	sessionCtx, cancelSessions := context.WithCancel(ctx)
	defer cancelSessions()
	s.maintenance.runMaintenance("startup persistence cleanup", func() {
		if err := s.maintenance.cleanupPersistentStores(sessionCtx, "startup"); err != nil {
			s.log.Warn("SQLite cleanup failed", "trigger", "startup", "error", err)
		}
	})
	s.maintenance.startRejectedMailCleanup(sessionCtx)
	if cleanupInterval := s.maintenance.cleanupInterval; cleanupInterval > 0 {
		maintenanceCtx, stopMaintenance := context.WithCancel(sessionCtx)
		maintenanceDone := make(chan struct{})
		go func() {
			defer close(maintenanceDone)
			ticker := time.NewTicker(cleanupInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					s.maintenance.runMaintenance("persistence cleanup", func() {
						if err := s.maintenance.cleanupPersistentStores(maintenanceCtx, "timer"); err != nil {
							s.log.Warn("SQLite cleanup failed", "error", err)
						}
					})
				case <-maintenanceCtx.Done():
					return
				}
			}
		}()
		defer func() {
			stopMaintenance()
			<-maintenanceDone
		}()
	}
	go func() { <-sessionCtx.Done(); _ = ln.Close() }()
	for {
		conn, err := s.acceptConnection(sessionCtx, ln)
		if err != nil {
			cancelSessions()
			s.wg.Wait()
			return err
		}
		if !s.peerAllowed(conn.RemoteAddr()) {
			s.log.Warn("rejected unauthorized Milter connection", "remote_addr", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		select {
		case s.sessionSlots <- struct{}{}:
		default:
			s.log.Warn("maximum simultaneous Milter connections reached", "max_connections", s.maxConnections, "remote_addr", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		logConnection := s.includeConnections
		started := time.Time{}
		localAddress, remoteAddress := "", ""
		if logConnection {
			started = time.Now()
			localAddress = conn.LocalAddr().String()
			remoteAddress = conn.RemoteAddr().String()
			s.log.Debug("Milter connection opened",
				"local_addr", localAddress,
				"remote_addr", remoteAddress,
				"active_connections", len(s.sessionSlots),
				"max_connections", s.maxConnections)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				_ = conn.Close()
				<-s.sessionSlots
				if logConnection {
					s.log.Debug("Milter connection closed",
						"local_addr", localAddress,
						"remote_addr", remoteAddress,
						"duration_ms", time.Since(started).Milliseconds(),
						"active_connections", len(s.sessionSlots),
						"max_connections", s.maxConnections)
				}
			}()
			s.handle(sessionCtx, conn)
		}()
	}
}

func (s *Server) acceptConnection(ctx context.Context, ln net.Listener) (net.Conn, error) {
	delay := time.Duration(0)
	for {
		conn, err := ln.Accept()
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		networkError, temporary := err.(net.Error)
		if !temporary || !networkError.Temporary() {
			return nil, err
		}
		if delay == 0 {
			delay = initialAcceptRetryDelay
		} else {
			delay *= 2
			if delay > maximumAcceptRetryDelay {
				delay = maximumAcceptRetryDelay
			}
		}
		s.log.Warn("temporary Milter listener error; retrying", "error", err, "retry_delay", delay.String())
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		}
	}
}

func peerPrefixes(entries []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return prefixes
}

func (s *Server) peerAllowed(remote net.Addr) bool {
	if remote == nil {
		return false
	}
	if remote.Network() == "unix" {
		return true
	}
	tcpAddress, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	addr, ok := netip.AddrFromSlice(tcpAddress.IP)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range s.allowedPeerIPs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// handle runs one Milter connection and isolates session panics from the
// listener and other active connections.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer s.recoverSessionPanic(ctx, conn)
	newSession(s.sessions, conn).run(ctx)
}

func (s *Server) recoverSessionPanic(ctx context.Context, conn net.Conn) {
	panicValue := recover()
	if panicValue == nil {
		return
	}
	closeErr := conn.Close()
	attrs := []any{"connection_closed", closeErr == nil}
	if closeErr != nil {
		attrs = append(attrs, "close_error", closeErr)
	}
	logRecoveredWorkerPanic(s.log, ctx, "milter session", panicValue, attrs...)
}

func logRecoveredWorkerPanic(log *slog.Logger, ctx context.Context, worker string, panicValue any, attrs ...any) {
	fields := []any{"worker", worker, "panic", fmt.Sprint(panicValue), "stack", string(debug.Stack())}
	fields = append(fields, attrs...)
	log.ErrorContext(ctx, "MilterGuard worker recovered from panic", fields...)
}
