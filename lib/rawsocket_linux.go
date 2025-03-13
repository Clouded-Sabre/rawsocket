//go:build linux

package lib

import (
	"fmt"
	"net"
	"os"
	"time"
)

// rawConnectionImpl is a simple concrete implementation of RawConnection
// that wraps a net.Conn. In a more advanced version you might use different
// implementations per platform.
type RawConnectionImpl struct {
	conn *net.IPConn
}

func (r *RawConnectionImpl) Read(b []byte) (int, error) {
	return r.conn.Read(b)
}

func (r *RawConnectionImpl) ReadFrom(b []byte) (int, net.Addr, error) {
	return r.conn.ReadFrom(b)
}

func (r *RawConnectionImpl) Write(b []byte) (int, error) {
	return r.conn.Write(b)
}

func (r *RawConnectionImpl) WriteTo(b []byte, addr net.Addr) (int, error) {
	return r.conn.WriteTo(b, addr)
}

func (r *RawConnectionImpl) SetReadDeadline(t time.Time) error {
	return r.conn.SetReadDeadline(t)
}

func (r *RawConnectionImpl) Close() error {
	return r.conn.Close()
}

func (r *RawConnectionImpl) LocalAddr() net.Addr {
	return r.conn.LocalAddr()
}

func (r *RawConnectionImpl) RemoteAddr() net.Addr {
	return r.conn.RemoteAddr()
}

// linuxRSCore implements RSCore for Linux using the standard net library.
type RSCoreImpl struct{}

// DialIP creates a new RawConnection by dialing a remote address.
func (l *RSCoreImpl) DialIP(network string, laddr *net.IPAddr, raddr *net.IPAddr) (RawConnection, error) {
	conn, err := net.DialIP(network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	return &RawConnectionImpl{conn: conn}, nil
}

// ListenIP creates a RawConnection by listening on the specified address.
// This example immediately accepts one incoming connection.
func (l *RSCoreImpl) ListenIP(network string, laddr *net.IPAddr) (RawConnection, error) {
	ipConn, err := net.ListenIP(network, laddr)
	if err != nil {
		return nil, err
	}
	return &RawConnectionImpl{conn: ipConn}, nil
}

func (l *RSCoreImpl) Close() error {
	return nil
}

// NewRSCore returns an RSCore instance. On Linux, it uses a dummy implementation; on other platforms, it initializes RawSocketCore.
func NewRSCore(config *RsConfig) (RSCore, error) {
	// Check if running as root or admin
	if !isAdmin() {
		fmt.Println("Rawsocket must be run as admin privilege on Windows or root privilege on Linux and macos.")
		os.Exit(1)
	}
	return &RSCoreImpl{}, nil
}

func NewRsConfig() *RsConfig {
	return &RsConfig{
		ArpCacheTimeout:   0,
		ArpRequestTimeout: 0,
		Debug:             false,
	}
}
