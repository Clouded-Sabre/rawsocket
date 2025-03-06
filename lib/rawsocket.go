package lib

import (
	"net"
	"time"
)

// RawConnection is an abstract interface that defines methods for a raw IP connection.
type RawConnection interface {
	// Read reads data from the connection.
	Read(b []byte) (int, error)
	// ReadFrom reads data from the connection.
	ReadFrom(b []byte) (int, net.Addr, error)
	// Write writes data to the connection.
	Write(b []byte) (int, error)
	// WriteTo writes data to the connection.
	WriteTo(b []byte, addr net.Addr) (int, error)
	// SetReadDeadline sets the deadline for future Read calls.
	SetReadDeadline(t time.Time) error
	// Close closes the connection.
	Close() error
	// getter functions
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// RSCore defines a unified interface for raw socket connections.
type RSCore interface {
	DialIP(network string, laddr *net.IPAddr, raddr *net.IPAddr) (RawConnection, error)
	ListenIP(network string, laddr *net.IPAddr) (RawConnection, error)
}

type RsConfig struct {
	ArpCacheTimeout, ArpRequestTimeout int
}
