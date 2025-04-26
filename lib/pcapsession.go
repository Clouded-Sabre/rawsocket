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
	"github.com/google/gopacket/pcap"
)

// pcapSession manages raw IP connections on the same iface
type pcapSessionConfig struct {
	arpRequestTimeout time.Duration
}
type pcapSessionParams struct {
	key                       string
	iface                     *net.Interface
	loopbackRerouteInputChan  chan *gopacket.Packet // Channel for for sending packets to rawsocketCore for loopback rerouting
	loopbackRerouteOutputChan chan *gopacket.Packet
	pcapSessionCloseSig       chan *pcapSession
	arpCache                  *ARPCache
}

type pcapSession struct {
	config             *pcapSessionConfig
	params             *pcapSessionParams
	handle             *pcap.Handle
	writeMu            sync.Mutex // Protect concurrent writes to pcap handle
	rawIPConnMap       sync.Map
	outgoingPackets    chan *gopacket.Packet // Channel for outgoing packets
	inArpPackets       chan *gopacket.Packet // Channel for ARP packets for handleArpReplies
	rawIPConnCloseChan chan *RawIPConn
	isLoopback         bool // true if the iface is a loopback interface
	stopChan           chan struct{}
	wg                 sync.WaitGroup
	isClosed           bool
}

// NewPcapSession creates a new NewPcapSession with a global ARP cache
func newPcapSession(params *pcapSessionParams, config *pcapSessionConfig) (*pcapSession, error) {
	// 1) Create an inactive handle so we can tune before activation
	inactive, err := pcap.NewInactiveHandle(getPcapDeviceName(params.iface))
	if err != nil {
		return nil, fmt.Errorf("pcap NewInactiveHandle: %w", err)
	}
	defer inactive.CleanUp()

	// 2) Tune the kernel buffer to 256 KiB (smaller = faster hand-off)
	if err := inactive.SetBufferSize(256 * 1024); err != nil {
		return nil, fmt.Errorf("SetBufferSize: %w", err)
	}

	// 3) Enable immediate mode → deliver packets as soon as they arrive, no batching
	if err := inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("SetImmediateMode: %w", err)
	}

	// 4) Minimal read timeout (1 ms) to guard against any residual buffering
	if err := inactive.SetTimeout(time.Millisecond); err != nil {
		return nil, fmt.Errorf("SetTimeout: %w", err)
	}

	// 5) Now activate the handle with all settings applied
	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("activate: %w", err)
	}

	// 6) Apply your BPF filter (IP + ARP)
	if err := handle.SetBPFFilter("ip or arp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("SetBPFFilter: %w", err)
	}

	// 7) Build the session
	session := &pcapSession{
		config:             config,
		params:             params,
		handle:             handle,
		outgoingPackets:    make(chan *gopacket.Packet, 100),
		inArpPackets:       make(chan *gopacket.Packet, 20),
		rawIPConnCloseChan: make(chan *RawIPConn),
		stopChan:           make(chan struct{}),
		wg:                 sync.WaitGroup{},
	}

	session.isLoopback = (params.iface.Flags & net.FlagLoopback) != 0

	session.wg.Add(1)
	go session.handleIncomingPackets()

	session.wg.Add(1)
	go session.handleOutgoingPackets()

	session.wg.Add(1)
	go session.handleRawIPConnClose()

	session.wg.Add(1)
	go session.handleArpReplies()

	return session, nil
}

func (ps *pcapSession) handleArpReplies() {
	defer ps.wg.Done()

	for {
		select {
		case <-ps.stopChan:
			log.Println("pcapSession.handleArpReplies: received stop signal. Exiting...")
			return
		case packet, ok := <-ps.inArpPackets:
			if !ok {
				log.Println("pcapSession.handleArpReplies: inArpPackets channel closed. Exiting...")
				return
			}

			arpLayer := (*packet).Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				if Debug {
					log.Println("pcapSession.handleArpReplies: No ARP layer found in packet")
				}
				continue
			}

			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				if Debug {
					log.Printf("pcapSession.handleArpReplies: Not an ARP reply (Operation: %d)", arp.Operation)
				}
				continue
			}

			// Update ARP cache
			srcIP := net.IP(arp.SourceProtAddress).String()
			srcMAC := net.HardwareAddr(arp.SourceHwAddress)

			if Debug {
				log.Printf("handleArpReplies: Caching ARP reply from IP %s -> MAC %s",
					srcIP, srcMAC)
			}

			ps.params.arpCache.Add(srcIP, srcMAC)
		}
	}
}

// DialIP creates or retrieves a RawIPConn based on the given parameters
func (ps *pcapSession) dialIP(srcIP, dstIP net.IP, protocol layers.IPProtocol) (*RawIPConn, error) {
	// construct RawIPConn key and lookup to see if it already exists
	key := srcIP.To4().String() + ":" + dstIP.To4().String() + ":" + protocolToString(protocol)
	if Debug {
		fmt.Println("DialIP: service key is", key)
	}
	if _, exists := ps.rawIPConnMap.Load(key); exists {
		return nil, fmt.Errorf("raw ip connection with the same source/destination IP and protocol type already exists. Cannot dial again")
	}

	// Create a new RawIPConn
	ipConnConfig := &RawIPConnConfig{
		localIP:  srcIP,
		remoteIP: dstIP,
		protocol: protocol,
	}
	ipConnParams := &RawIPConnParams{
		isServer:           false,
		key:                key,
		pcapIface:          ps.params.iface,
		handle:             ps.handle,
		outputChan:         ps.outgoingPackets,
		rawIPConnCloseChan: ps.rawIPConnCloseChan,
	}
	conn, err := NewRawIPConn(ipConnParams, ipConnConfig)
	if err != nil {
		log.Fatalln("Error dialing raw IPConn:", err)
	}

	// Add to map
	ps.rawIPConnMap.Store(key, conn)
	return conn, nil
}

func protocolToString(protocol layers.IPProtocol) string {
	switch protocol {
	case layers.IPProtocolUDP:
		return "UDP"
	case layers.IPProtocolTCP:
		return "TCP"
	case layers.IPProtocolICMPv4:
		return "ICMP"
	// Add any other protocols you are interested in
	default:
		return fmt.Sprintf("protocol_%d", protocol) // Default case for unknown protocols
	}
}

func (ps *pcapSession) listenIP(ip net.IP, protocol layers.IPProtocol) (*RawIPConn, error) {
	// Create a unique key for the RawIPConn
	connKey := fmt.Sprintf("%s:%s", ip.String(), protocolToString(protocol))
	if Debug {
		log.Println("pcapSession.listenIP: service key is", connKey)
	}

	_, exists := ps.rawIPConnMap.Load(connKey)
	if exists {
		return nil, fmt.Errorf("IPConn Listener already exists for IP: %v and protocol: %v", ip, protocol)
	}

	// Create a new RawIPConn
	ipConnConfig := &RawIPConnConfig{
		localIP:  ip,
		remoteIP: nil,
		protocol: protocol,
	}
	ipConnParams := &RawIPConnParams{
		isServer:           true,
		key:                connKey,
		pcapIface:          ps.params.iface,
		handle:             ps.handle,
		outputChan:         ps.outgoingPackets,
		rawIPConnCloseChan: ps.rawIPConnCloseChan,
	}
	conn, err := NewRawIPConn(ipConnParams, ipConnConfig)
	if err != nil {
		log.Fatalln("Error dialing raw IPConn:", err)
	}

	// Add to map
	ps.rawIPConnMap.Store(connKey, conn)
	return conn, nil
}

func (ps *pcapSession) handleIncomingPackets() {
	defer ps.wg.Done()

	// Check if the interface is a loopback interface
	var decoder gopacket.Decoder
	if (ps.params.iface.Flags & net.FlagLoopback) != 0 {
		decoder = layers.LayerTypeLoopback
	} else {
		decoder = layers.LayerTypeEthernet
	}

	src := gopacket.NewPacketSource(ps.handle, decoder)
	in := src.Packets()
	defer ps.handle.Close()
	for {
		select {
		case <-ps.stopChan:
			return
		case packet, ok := <-in:
			if !ok {
				// Channel closed
				return
			}
			ps.processIncomingPacket(&packet)
		}
	}
}

// processPacket processes an incoming packet and forwards it to the appropriate RawIPConn
func (ps *pcapSession) processIncomingPacket(packet *gopacket.Packet) {
	/*globalDebug := Debug
	Debug = true                           // Enable debug logging for this function
	defer func() { Debug = globalDebug }() // Restore original debug state
	*/

	if Debug {
		log.Printf("pcapSession.processIncomingPacket(%s): start processing packet.\n", ps.params.iface.Name)
	}
	startTime := time.Now() // Start timing

	// Check for ARP packets first
	if arpLayer := (*packet).Layer(layers.LayerTypeARP); arpLayer != nil {
		if Debug {
			log.Printf("pcapSession.processIncomingPacket(%s): Forwarding ARP packet to handler\n", ps.params.iface.Name)
		}
		ps.inArpPackets <- packet
		return
	}

	// Continue with IPv4 processing
	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		if Debug {
			log.Printf("pcapSession.processIncomingPacket(%s): Not an IPv4 packet\n", ps.params.iface.Name)
		}
		return
	}

	ipv4, ok := ipLayer.(*layers.IPv4)
	if !ok {
		if Debug {
			log.Printf("pcapSession.processIncomingPacket(%s): Failed to parse IPv4 layer\n", ps.params.iface.Name)
		}
		return
	}

	// Create a complete copy of the IPv4 packet including header and payload
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts,
		ipv4,
		gopacket.Payload(ipv4.Payload),
	)
	if err != nil {
		if Debug {
			log.Printf("pcapSession.processIncomingPacket(%s): Failed to serialize IPv4 packet: %s\n", ps.params.iface.Name, err)
		}
		return
	}
	newIpPacket := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	// rerouting logic for loopback interface
	// Some OSes send packets of internal communication via loopback interface even if the destination is a local non-loopback IP
	if ps.isLoopback && !ipv4.DstIP.IsLoopback() {
		if Debug {
			log.Printf("pcapSession.processIncomingPacket(%s): reroute non-loopback packet (dst: %s) to loopback pcapSession\n", ps.params.iface.Name, ipv4.DstIP)
		}
		ps.params.loopbackRerouteInputChan <- &newIpPacket
		return
	}

	// Determine the Layer 4 protocol
	protocol := ipv4.Protocol

	// Debugging: Print all client connections in rawIPConnMap
	/*if Debug {
		fmt.Println("Debug: Listing all client connections in ps.rawIPConnMap:")
		ps.rawIPConnMap.Range(func(key, value interface{}) bool {
			fmt.Printf("Client connection key: %s\n", key)
			return true // continue iterating
		})
	}*/

	// Construct the client connection key for RawIPConn lookup
	key := ipv4.DstIP.String() + ":" + ipv4.SrcIP.String() + ":" + protocol.String()
	if Debug {
		log.Printf("pcapSession.processIncomingPacket(%s): Client key is %s\n", ps.params.iface.Name, key)
	}
	value, exists := ps.rawIPConnMap.Load(key)
	if exists {
		conn := value.(*RawIPConn)
		if Debug {
			log.Printf("pcapSession.processIncomingPacket(%s): Forwarding IP packet to client inputChan of %s\n", ps.params.iface.Name, key)
		}

		conn.inputChan <- &newIpPacket

		if Debug {
			log.Printf("pcapSession.processIncomingPacket(%s): Time taken: %v\n", ps.params.iface.Name, time.Since(startTime))
		}
		return
	}

	// Construct the server connection key for RawIPConn lookup
	key = ipv4.DstIP.String() + ":" + protocol.String()
	if Debug {
		log.Printf("pcapSession.processIncomingPacket(%s): Server key is %s\n", ps.params.iface.Name, key)
	}
	value, exists = ps.rawIPConnMap.Load(key)
	if exists {
		conn := value.(*RawIPConn)
		if Debug {
			log.Printf("pcapSession.processIncomingPacket(%s): Forwarding IP packet to server inputChan of %s\n", ps.params.iface.Name, key)
		}

		conn.inputChan <- &newIpPacket
		return
	}

	if Debug {
		log.Printf("pcapSession.processIncomingPacket(%s): No RawIPConn found for key: %s\n", ps.params.iface.Name, key)
	}
}

func (ps *pcapSession) handleOutgoingPackets() {
	Debug := true // Enable debug logging for this function
	defer ps.wg.Done()

	for {
		select {
		case <-ps.stopChan:
			return
		case pkt := <-ps.outgoingPackets:
			startTime := time.Now()
			if Debug {
				log.Printf("handleOutgoingPackets: outgoingPackets channel length: %d/%d",
					len(ps.outgoingPackets), cap(ps.outgoingPackets))
			}
			var buffer gopacket.SerializeBuffer
			var err error
			options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

			ipLayer := (*pkt).Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				log.Println("pcapSession.handleOutgoingPackets: packet does not contain an IPv4 layer")
				continue
			}

			ipv4, _ := ipLayer.(*layers.IPv4)
			destIP := ipv4.DstIP

			if Debug {
				log.Printf("handleOutgoingPackets: Packet preparation middle, time taken: %v", time.Since(startTime))
				startTime = time.Now()
			}

			if ps.isLoopback {
				buffer = gopacket.NewSerializeBuffer()
				err = serializeLoopbackPacket(buffer, options, (*pkt).Data())
				if err != nil {
					log.Println("Error serializing loopback packet:", err)
					continue
				}
			} else {
				srcIsLocal := isLocalIP(ipv4.SrcIP)
				dstIsLocal := isLocalIP(ipv4.DstIP)
				if srcIsLocal && dstIsLocal {
					if Debug {
						log.Printf("Non-loopback interface: forwarding local packet (src: %s, dst: %s) to reroute channel",
							ipv4.SrcIP, ipv4.DstIP)
					}
					ps.params.loopbackRerouteOutputChan <- pkt
					continue
				}

				_, _, gatewayIP, _ := GetLocalIP(destIP)
				var nextHopIp = destIP
				if gatewayIP != nil {
					nextHopIp = gatewayIP
				}
				dstMAC, err := getRemoteMAC(ps.params.iface, nextHopIp, ps.config.arpRequestTimeout, ps.params.arpCache, ps)
				if err != nil {
					log.Println("pcapSession.handleOutgoingPackets: failed to retrieve remote mac address:", err)
					continue
				}

				buffer = gopacket.NewSerializeBuffer()
				ethernetLayer := &layers.Ethernet{
					SrcMAC:       ps.params.iface.HardwareAddr,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv4,
				}
				err = gopacket.SerializeLayers(buffer, options,
					ethernetLayer,
					gopacket.Payload((*pkt).Data()))
				if err != nil {
					log.Println("Error serializing ethernet packet:", err)
					continue
				}
			}

			if Debug {
				log.Printf("handleOutgoingPackets: Packet preparation ready, time taken: %v", time.Since(startTime))
			}

			ps.writeMu.Lock()
			err = ps.handle.WritePacketData(buffer.Bytes())
			ps.writeMu.Unlock()

			if err != nil {
				log.Printf("Error writing packet: %v", err)
			}
		}
	}
}

func (ps *pcapSession) handleRawIPConnClose() {
	defer ps.wg.Done()

	for {
		select {
		case <-ps.stopChan:
			return
		case conn := <-ps.rawIPConnCloseChan:
			ps.rawIPConnMap.Delete(conn.getKey())

			if mapLength(&(ps.rawIPConnMap)) == 0 {
				// Start a timeout timer for 10 seconds
				timer := time.NewTimer(10 * time.Second)
				defer timer.Stop()

				select {
				case <-ps.stopChan:
					return
				case <-timer.C:
					if mapLength(&(ps.rawIPConnMap)) == 0 {
						ps.close() // Close the pcapsession if empty after timeout
					}
				}
			}
		}
	}
}

func (ps *pcapSession) close() {
	if ps.isClosed {
		return
	}
	ps.isClosed = true

	// First collect all RawIPConns to close
	var ipConns []*RawIPConn
	ps.rawIPConnMap.Range(func(key, value interface{}) bool {
		ipConns = append(ipConns, value.(*RawIPConn))
		return true // continue iteration
	})

	// Close all RawIPConns
	for _, ipConn := range ipConns {
		ipConn.Close()
	}

	// Signal all goroutines to stop
	close(ps.stopChan)

	// Wait for all goroutines to finish
	ps.wg.Wait()

	// Close all channels
	close(ps.outgoingPackets)
	close(ps.inArpPackets)

	// Close the pcap handle
	ps.handle.Close()

	log.Printf("Pcap Session %s closed", ps.params.key)
}

func mapLength(m *sync.Map) int {
	count := 0
	m.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

func isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}
