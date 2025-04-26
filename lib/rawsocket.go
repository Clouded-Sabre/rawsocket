package lib

import (
	"net"
	"time"
)

// RawConnection is an abstract interface that defines methods for a raw IP connection.
type RawConnection interface {
	// Read reads data from the connection.
	// It returns the number of bytes read and an error, if any.
	// The data which holds the entire ip packet (including ip header)
	// is read into the provided byte slice b.
	Read(b []byte) (int, error)
	// ReadFrom reads data from the connection.
	// It returns the number of bytes read, source ip address of the ip packet, and an error, if any.
	// The data which holds the ip packet's payload only (excluding ip header)
	// is read into the provided byte slice b.
	ReadFrom(b []byte) (int, net.Addr, error)
	// Write writes data to the connection.
	// the data should holds only the ip packet's payload (excluding ip header)
	// It returns the number of bytes written and an error, if any.
	// source and destination IP addresses are automatically set in the IP header using RawIPConn's local and remote addresses.
	// L4 protocol type is also automatically set in the IP header using RawIPConn's protocol type.
	Write(b []byte) (int, error)
	// WriteTo writes data to the connection.
	// addr is the destination address to which the data should be sent.
	// the data should holds only the ip packet's payload (excluding ip header)
	// It returns the number of bytes written and an error, if any.
	// source IP addresses are automatically set in the IP header using RawIPConn's local addresses.
	// L4 protocol type is also automatically set in the IP header using RawIPConn's protocol type.
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
	// DialIP creates a new RawConnection by dialing a remote address. like net lib's IPConn.DialIP,
	// network string must be in the form of "ip4:icmp", etc. (i.e. "ip"|"ip4"|"ip6" plus protocol name or number)
	// laddr and raddr are the local and remote IP addresses, respectively.
	// if laddr is nil, a local IP address which is routable to raddr will be chosen automatically.
	DialIP(network string, laddr *net.IPAddr, raddr *net.IPAddr) (RawConnection, error)
	// ListenIP creates a RawConnection by listening on the specified address. like net lib's IPConn.ListenIP
	// network string must be in the form of "ip4:icmp", etc. (i.e. "ip"|"ip4"|"ip6" plus protocol name or number)
	// laddr is the local IP address to listen on.
	ListenIP(network string, laddr *net.IPAddr) (RawConnection, error)
	Close() error
}

type RsConfig struct {
	ArpCacheTimeout, ArpRequestTimeout int
	Debug                              bool
}
