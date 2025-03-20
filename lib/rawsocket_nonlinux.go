//go:build windows || darwin
// +build windows darwin

package lib

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

var (
	globalCore     *RawSocketCore
	globalCoreOnce sync.Once
)

// rawConnectionNonLinuxImpl implements the RawConnection interface using rawsocket.
type rawConnectionNonLinuxImpl struct {
	conn *RawIPConn
}

func (r *rawConnectionNonLinuxImpl) Read(b []byte) (int, error) {
	return r.conn.Read(b)
}

func (r *rawConnectionNonLinuxImpl) ReadFrom(b []byte) (int, net.Addr, error) {
	return r.conn.ReadFrom(b)
}

func (r *rawConnectionNonLinuxImpl) Write(b []byte) (int, error) {
	return r.conn.Write(b)
}

func (r *rawConnectionNonLinuxImpl) WriteTo(b []byte, addr net.Addr) (int, error) {
	return r.conn.WriteTo(b, addr)
}

func (r *rawConnectionNonLinuxImpl) SetReadDeadline(t time.Time) error {
	return r.conn.SetReadDeadline(t)
}

func (r *rawConnectionNonLinuxImpl) Close() error {
	return r.conn.Close()
}

func (r *rawConnectionNonLinuxImpl) LocalAddr() net.Addr {
	return &net.IPAddr{IP: r.conn.LocalIP()}
}

func (r *rawConnectionNonLinuxImpl) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: r.conn.RemoteIP()}
}

// nonLinuxRSCore implements RSCore for Windows and macOS using rawsocket.
type RSCoreImpl struct {
	core *RawSocketCore
}

// DialIP creates a new RawConnection by dialing a remote address using rawsocket.
// The network parameter is expected to be in the format "ip4:<protocol>" (e.g., "ip4:tcp").
func (n *RSCoreImpl) DialIP(network string, laddr *net.IPAddr, raddr *net.IPAddr) (RawConnection, error) {
	parts := strings.Split(network, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid network format: %s", network)
	}

	var protocol layers.IPProtocol
	if protoID, err := strconv.Atoi(parts[1]); err == nil {
		protocol = layers.IPProtocol(protoID) // Handle numeric protocol ID
	} else {
		switch strings.ToLower(parts[1]) {
		case "tcp":
			protocol = layers.IPProtocolTCP
		case "udp":
			protocol = layers.IPProtocolUDP
		case "icmp":
			protocol = layers.IPProtocolICMPv4
		default:
			return nil, fmt.Errorf("unsupported protocol: %s", parts[1])
		}
	}

	rawConn, err := n.core.DialIP(protocol, laddr.IP, raddr.IP)
	if err != nil {
		return nil, err
	}

	return &rawConnectionNonLinuxImpl{conn: rawConn}, nil
}

// ListenIP creates a RawConnection by listening on the specified address using rawsocket.
// The network parameter is expected to be in the format "ip4:<protocol>".
func (n *RSCoreImpl) ListenIP(network string, laddr *net.IPAddr) (RawConnection, error) {
	parts := strings.Split(network, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid network format: %s", network)
	}

	var protocol layers.IPProtocol
	if protoID, err := strconv.Atoi(parts[1]); err == nil {
		protocol = layers.IPProtocol(protoID) // Handle numeric protocol ID
	} else {
		switch strings.ToLower(parts[1]) {
		case "tcp":
			protocol = layers.IPProtocolTCP
		case "udp":
			protocol = layers.IPProtocolUDP
		case "icmp":
			protocol = layers.IPProtocolICMPv4
		default:
			return nil, fmt.Errorf("unsupported protocol: %s", parts[1])
		}
	}

	rawConn, err := n.core.ListenIP(laddr.IP, protocol)
	if err != nil {
		return nil, err
	}
	return &rawConnectionNonLinuxImpl{conn: rawConn}, nil
}

func (n *RSCoreImpl) Close() error {
	return n.core.Close()
}

// NewGlobalCore initializes and returns a RawSocketCore for non-linux platforms.
func NewGlobalCore(arpCacheTimeout, arpRequestTimeout int, debug bool) *RawSocketCore {
	globalCoreOnce.Do(func() {
		globalCore = NewRawSocketCore(arpCacheTimeout, arpRequestTimeout, debug)
	})
	return globalCore
}

// NewRSCore returns an RSCore instance. On Linux, it uses a dummy implementation; on other platforms, it initializes RawSocketCore.
func NewRSCore(config *RsConfig) (RSCore, error) {
	// Check if running as root or admin
	if !isAdmin() {
		fmt.Println("Rawsocket must be run as admin privilege on Windows or root privilege on Linux and macos.")
		os.Exit(1)
	}
	return &RSCoreImpl{core: NewGlobalCore(config.ArpCacheTimeout, config.ArpRequestTimeout, config.Debug)}, nil
}

func NewDefaultRsConfig() *RsConfig {
	return &RsConfig{
		ArpCacheTimeout:   arpCacheTimeoutDefault,
		ArpRequestTimeout: arpRequestTimeoutDefault,
		Debug:             false,
	}
}
