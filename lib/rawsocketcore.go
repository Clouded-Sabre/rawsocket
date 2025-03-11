//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package lib

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type RawSocketCore struct {
	mu                  sync.RWMutex
	pcapSessionMap      map[string]*pcapSession
	arpCacheTimeout     time.Duration
	arpRequestTimeout   time.Duration
	pcapSessionCloseSig chan *pcapSession
	arpCache            *ARPCache
	stopChan            chan struct{}
	wg                  sync.WaitGroup
	isClosed            bool
}

var Debug = false

func NewRawSocketCore(arpCacheTimeout, arpRequestTimeout int, debug bool) *RawSocketCore {
	core := &RawSocketCore{
		pcapSessionMap:      make(map[string]*pcapSession),
		arpCacheTimeout:     time.Duration(arpCacheTimeout) * time.Second,
		arpRequestTimeout:   time.Duration(arpRequestTimeout) * time.Second,
		pcapSessionCloseSig: make(chan *pcapSession),
		arpCache:            NewARPCache(time.Duration(arpCacheTimeout) * time.Second),
		stopChan:            make(chan struct{}),
		wg:                  sync.WaitGroup{},
	}

	Debug = debug

	core.wg.Add(1)
	go core.handlePcapSessionClose()

	return core
}

func (core *RawSocketCore) DialIP(protocol layers.IPProtocol, srcIP, dstIP net.IP) (*RawIPConn, error) {
	var (
		err       error
		iface     *net.Interface
		gatewayIP net.IP
	)

	// Step 1: Determine the local IP used for source IP
	if srcIP == nil {
		// Determine the local IP routable to the destination
		srcIP, iface, gatewayIP, err = GetLocalIP(dstIP)
		if err != nil {
			return nil, err
		}
	} else {
		// Ensure srcIP is one of the local interfaces
		iface, err = findInterfaceByIP(srcIP)
		if err != nil {
			return nil, fmt.Errorf("provided srcIP %v is not a local IP: %v", srcIP, err)
		}
	}
	if gatewayIP != nil {
		if Debug {
			log.Println("interface name is", iface.Name, " Gateway IP is", gatewayIP, " source ip is", srcIP)
		}
	} else {
		log.Println("interface name is", iface.Name, " Gateway IP is <nil>", " source ip is", srcIP)
	}

	// first we need to check if there is an pcapSession already listening at this iface
	core.mu.Lock()
	ps, exists := core.pcapSessionMap[iface.Name]
	core.mu.Unlock()

	if !exists {
		conf := &pcapSessionConfig{
			arpRequestTimeout: core.arpRequestTimeout,
		}

		params := &pcapSessionParams{
			key:                 iface.Name,
			iface:               iface,
			pcapSessionCloseSig: core.pcapSessionCloseSig,
			arpCache:            core.arpCache,
			// handle will be added in NewPcapSession
		}

		ps, err = newPcapSession(params, conf)
		if err != nil {
			return nil, err
		}

		core.mu.Lock()
		core.pcapSessionMap[iface.Name] = ps
		core.mu.Unlock()
	}

	conn, err := ps.dialIP(srcIP, dstIP, protocol)
	if err != nil {
		return nil, err
	}

	ps.rawIPConnMap.Store(conn.getKey(), conn)

	return conn, nil
}

func (core *RawSocketCore) ListenIP(ip net.IP, protocol layers.IPProtocol) (*RawIPConn, error) {
	// Find the appropriate interface for the given IP
	iface, err := findInterfaceByIP(ip)
	if err != nil {
		return nil, fmt.Errorf("interface not found for IP: %v", err)
	}

	// Look up or create a pcap session for the interface
	psKey := iface.Name
	core.mu.Lock()
	ps, ok := core.pcapSessionMap[psKey]
	core.mu.Unlock()
	if !ok {
		conf := &pcapSessionConfig{
			arpRequestTimeout: core.arpRequestTimeout,
		}

		params := &pcapSessionParams{
			key:                 iface.Name,
			iface:               iface,
			pcapSessionCloseSig: core.pcapSessionCloseSig,
			arpCache:            core.arpCache,
			// handle will be added in NewPcapSession
		}
		ps, err = newPcapSession(params, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create pcap session: %v", err)
		}
		core.mu.Lock()
		core.pcapSessionMap[psKey] = ps
		core.mu.Unlock()
	}

	conn, err := ps.listenIP(ip, protocol)
	if err != nil {
		return nil, fmt.Errorf("rawSocketCore.ListenIP: %s", err)
	}

	return conn, nil
}

func (core *RawSocketCore) handlePcapSessionClose() {
	defer core.wg.Done()

	for {
		select {
		case <-core.stopChan:
			return
		case ps := <-core.pcapSessionCloseSig:
			core.mu.Lock()
			delete(core.pcapSessionMap, ps.params.key)
			core.mu.Unlock()
		}
	}
}

func (core *RawSocketCore) Close() {
	if core.isClosed {
		return
	}
	core.isClosed = true

	var pcapSessions []*pcapSession
	core.mu.Lock()
	for _, session := range core.pcapSessionMap {
		pcapSessions = append(pcapSessions, session)
	}
	core.mu.Unlock()

	for _, session := range pcapSessions {
		session.close()
	}

	close(core.stopChan)

	log.Println("Raw Socket Core: waiting for go routine to close")
	core.wg.Wait()
	log.Println("Raw Socket Core: go routine closed")

	close(core.pcapSessionCloseSig)
	core.arpCache.Close()

	log.Println("Raw socket core stopped.")
}
