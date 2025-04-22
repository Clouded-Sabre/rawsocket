//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package lib

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type RawSocketCore struct {
	mu                        sync.RWMutex
	pcapSessionMap            map[string]*pcapSession
	loopbackRerouteInputChan  chan *gopacket.Packet
	loopbackRerouteOutputChan chan *gopacket.Packet
	loopbackPcapSession       *pcapSession
	arpCacheTimeout           time.Duration
	arpRequestTimeout         time.Duration
	pcapSessionCloseSig       chan *pcapSession
	arpCache                  *ARPCache
	stopChan                  chan struct{}
	wg                        sync.WaitGroup
	isClosed                  bool
}

var Debug = false

const (
	arpCacheTimeoutDefault   = 300 // 5 minutes
	arpRequestTimeoutDefault = 2   // seconds
)

func NewRawSocketCore(arpCacheTimeout, arpRequestTimeout int, debug bool) *RawSocketCore {
	core := &RawSocketCore{
		pcapSessionMap:            make(map[string]*pcapSession),
		loopbackRerouteInputChan:  make(chan *gopacket.Packet),
		loopbackRerouteOutputChan: make(chan *gopacket.Packet),
		arpCacheTimeout:           time.Duration(arpCacheTimeout) * time.Second,
		arpRequestTimeout:         time.Duration(arpRequestTimeout) * time.Second,
		pcapSessionCloseSig:       make(chan *pcapSession),
		arpCache:                  NewARPCache(time.Duration(arpCacheTimeout) * time.Second),
		stopChan:                  make(chan struct{}),
		wg:                        sync.WaitGroup{},
	}

	Debug = debug

	// Find loopback interfaces and create loopback pcap sessions
	loIfaces, err := getLoopbackInterfaces()
	if err != nil {
		return nil
	}

	// Use the first loopback interface as the main one
	loConfig := &pcapSessionConfig{
		arpRequestTimeout: time.Duration(arpRequestTimeout) * time.Second,
	}

	// Create pcap sessions for all loopback interfaces
	for _, loIface := range loIfaces {
		loParams := &pcapSessionParams{
			key:                      loIface.Name,
			iface:                    loIface,
			loopbackRerouteInputChan: core.loopbackRerouteInputChan,
			pcapSessionCloseSig:      core.pcapSessionCloseSig,
			arpCache:                 core.arpCache,
		}

		ps, err := newPcapSession(loParams, loConfig)
		if err != nil {
			continue // Skip this interface if we can't create a session
		}

		core.pcapSessionMap[loIface.Name] = ps
		if core.loopbackPcapSession == nil {
			core.loopbackPcapSession = ps // Use first successful session as main loopback
		}
	}

	if core.loopbackPcapSession == nil {
		return nil // No loopback interface could be initialized
	}

	core.wg.Add(1)
	go core.handlePcapSessionClose()

	go core.handleLoopbackRerouteInputPackets()
	go core.handleLoopbackRerouteOutputPackets()

	return core
}

func getLoopbackInterfaces() ([]*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var loopbacks []*net.Interface
	for i := range interfaces {
		if interfaces[i].Flags&net.FlagLoopback != 0 {
			loopbacks = append(loopbacks, &interfaces[i])
		}
	}

	if len(loopbacks) == 0 {
		return nil, fmt.Errorf("no loopback interface found")
	}

	return loopbacks, nil
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
			key:                       iface.Name,
			loopbackRerouteInputChan:  core.loopbackRerouteInputChan,
			loopbackRerouteOutputChan: core.loopbackRerouteOutputChan,
			iface:                     iface,
			pcapSessionCloseSig:       core.pcapSessionCloseSig,
			arpCache:                  core.arpCache,
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
			key:                       iface.Name,
			loopbackRerouteInputChan:  core.loopbackRerouteInputChan,
			loopbackRerouteOutputChan: core.loopbackRerouteOutputChan,
			iface:                     iface,
			pcapSessionCloseSig:       core.pcapSessionCloseSig,
			arpCache:                  core.arpCache,
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

func (core *RawSocketCore) handleLoopbackRerouteInputPackets() {
	core.wg.Add(1)
	defer core.wg.Done()

	for {
		select {
		case <-core.stopChan:
			return
		case packet := <-core.loopbackRerouteInputChan:
			// Extract IP layer
			ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				if Debug {
					log.Println("handleLoopbackRerouteInputPackets: Not an IPv4 packet")
				}
				continue
			}

			ipv4, ok := ipLayer.(*layers.IPv4)
			if !ok {
				if Debug {
					log.Println("handleLoopbackRerouteInputPackets: Failed to parse IPv4 layer")
				}
				continue
			}

			// Search all pcap sessions for matching connection based on destination IP
			core.mu.RLock()
			found := false
			for _, session := range core.pcapSessionMap {
				// Skip loopback session
				if session.isLoopback {
					continue
				}

				// Search through all connections in this session
				session.rawIPConnMap.Range(func(key, value interface{}) bool {
					conn := value.(*RawIPConn)
					// Check if this connection's local IP matches packet's destination IP
					if conn.config.localIP.Equal(ipv4.DstIP) {
						if Debug {
							log.Printf("handleLoopbackRerouteInputPackets: Found matching connection for dst=%s", ipv4.DstIP)
						}
						conn.inputChan <- packet
						found = true
						return false // stop iterating
					}
					return true // continue iterating
				})

				if found {
					break
				}
			}
			core.mu.RUnlock()

			if !found && Debug {
				log.Printf("handleLoopbackRerouteInputPackets: No connection found for packet dst=%s src=%s proto=%s",
					ipv4.DstIP, ipv4.SrcIP, ipv4.Protocol)
			}
		}
	}
}

func (core *RawSocketCore) handleLoopbackRerouteOutputPackets() {
	core.wg.Add(1)
	defer core.wg.Done()

	for {
		select {
		case <-core.stopChan:
			return
		case packet := <-core.loopbackRerouteOutputChan:
			if core.loopbackPcapSession != nil && packet != nil {
				core.loopbackPcapSession.outgoingPackets <- packet
			}
		}
	}
}

func (core *RawSocketCore) Close() error {
	if core.isClosed {
		return nil
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

	return nil
}
