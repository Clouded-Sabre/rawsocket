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
	key                 string
	iface               *net.Interface
	handle              *pcap.Handle
	pcapSessionCloseSig chan *pcapSession
	arpCache            *ARPCache
}

type pcapSession struct {
	config *pcapSessionConfig
	params *pcapSessionParams
	//mu                 sync.Mutex
	rawIPConnMap       sync.Map
	outgoingPackets    chan *gopacket.Packet // Channel for outgoing packets
	rawIPConnCloseChan chan *RawIPConn
	stopChan           chan struct{}
	wg                 sync.WaitGroup
	isClosed           bool
}

// NewPcapSession creates a new NewPcapSession with a global ARP cache
func newPcapSession(params *pcapSessionParams, config *pcapSessionConfig) (*pcapSession, error) {
	var err error
	params.handle, err = pcap.OpenLive(getPcapDeviceName(params.iface), 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	session := &pcapSession{
		config: config,
		params: params,
		//rawIPConnMap:       make(map[string]*RawIPConn),
		outgoingPackets:    make(chan *gopacket.Packet, 100),
		rawIPConnCloseChan: make(chan *RawIPConn),
		stopChan:           make(chan struct{}),
		wg:                 sync.WaitGroup{},
	}

	session.wg.Add(1)
	go session.handleIncomingPackets()

	session.wg.Add(1)
	go session.handleOutgoingPackets()

	session.wg.Add(1)
	go session.handleRawIPConnClose()

	return session, nil
}

// DialIP creates or retrieves a RawIPConn based on the given parameters
func (ps *pcapSession) dialIP(srcIP, dstIP net.IP, protocol layers.IPProtocol) (*RawIPConn, error) {
	//ps.mu.Lock()
	//defer ps.mu.Unlock()

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
		handle:             ps.params.handle,
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
		handle:             ps.params.handle,
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

	src := gopacket.NewPacketSource(ps.params.handle, decoder)
	in := src.Packets()
	defer ps.params.handle.Close()
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
	// Extract the IPv4 layer
	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		if Debug {
			log.Println("Not an IPv4 packet")
		}
		return
	}

	ipv4, ok := ipLayer.(*layers.IPv4)
	if !ok {
		if Debug {
			log.Println("Failed to parse IPv4 layer")
		}
		return
	}

	// Determine the Layer 4 protocol
	protocol := ipv4.Protocol

	// Debugging: Print all client connections in rawIPConnMap
	if Debug {
		fmt.Println("Debug: Listing all client connections in ps.rawIPConnMap:")
		ps.rawIPConnMap.Range(func(key, value interface{}) bool {
			fmt.Printf("Client connection key: %s\n", key)
			return true // continue iterating
		})
	}

	// Construct the client connection key for RawIPConn lookup
	key := ipv4.DstIP.String() + ":" + ipv4.SrcIP.String() + ":" + protocol.String()
	if Debug {
		log.Println("pcapSession:processIncomingPacket: Client key is", key)
	}
	value, exists := ps.rawIPConnMap.Load(key)
	if exists {
		conn := value.(*RawIPConn)
		if Debug {
			fmt.Printf("pcapSession->processIncomingPacket: Forwarding packet to client inputChan of %s\n", key)
		}
		// Forward the packet to the RawIPConn's input channel
		conn.inputChan <- packet
		return
	}

	// Construct the server connection key for RawIPConn lookup
	key = ipv4.DstIP.String() + ":" + protocol.String()
	if Debug {
		log.Println("Server key is", key)
	}
	value, exists = ps.rawIPConnMap.Load(key)
	if exists {
		conn := value.(*RawIPConn)
		if Debug {
			fmt.Printf("pcapSession->processIncomingPacket: Forwarding packet to server inputChan of %s\n", key)
		}
		// Forward the packet to the RawIPConn's input channel
		conn.inputChan <- packet
		return
	}

	/*// Check for TCP 3-way handshake packets originated locally
	if protocol != layers.IPProtocolTCP {
		tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Construct the client connection key (outbound packet) for RawIPConn lookup
			key = ipv4.SrcIP.String() + ":" + ipv4.DstIP.String() + ":" + protocol.String()
			ps.sendSynPacket(packet, key, tcp)

			// Construct the server connection key for RawIPConn lookup
			key = ipv4.SrcIP.String() + ":" + protocol.String()
			ps.sendSynPacket(packet, key, tcp)
		}
	}*/

	if Debug {
		log.Println("No RawIPConn found for key:", key)
	}
}

/*func (ps *pcapSession) sendSynPacket(packet *gopacket.Packet, key string, tcp *layers.TCP) {
	value, exists := ps.rawIPConnMap.Load(key)
	if exists {
		// Check for SYN/SYN-ACK packet
		if tcp.SYN || (tcp.ACK && len(tcp.Payload) == 0) {
			if Debug {
				log.Println("Detected locally originated SYN or zero-length ACK packet")
			}
			conn := value.(*RawIPConn)
			// Forward the packet to the RawIPConn's input channel. Note that it's RawIPConn's resposiblity to tell which ACK belongs to 3-way handshake
			conn.inputChan <- packet
			return
		}
	}
}*/

func (ps *pcapSession) handleOutgoingPackets() {
	defer ps.wg.Done()

	for {
		select {
		case <-ps.stopChan:
			return
		case pkt := <-ps.outgoingPackets:
			var buffer gopacket.SerializeBuffer
			var err error
			options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

			if (ps.params.iface.Flags & net.FlagLoopback) != 0 {
				// Loopback interface: No Ethernet layer
				buffer = gopacket.NewSerializeBuffer()
				// Used for loopback interface
				lo := layers.Loopback{
					Family: layers.ProtocolFamilyIPv4,
				}
				err = gopacket.SerializeLayers(buffer, options, &lo, gopacket.Payload((*pkt).Data()))
				if err != nil {
					log.Println("Error serializing packet:", err)
					continue
				}
			} else { // currently we only support ethernet besides loopback
				// Ethernet interface: Add Ethernet layer
				// get pkt's destination ip
				ipLayer := (*pkt).Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					log.Println("pcapSession.handleOutgoingPackets: packet does not contain an IPv4 layer")
					continue // skip the packet
				}

				ipv4, _ := ipLayer.(*layers.IPv4)
				destIP := ipv4.DstIP

				// find out nextHopIP
				_, _, gatewayIP, _ := GetLocalIP(destIP)
				var nextHopIp = destIP
				if gatewayIP != nil {
					nextHopIp = gatewayIP
				}
				// get remote mac address of nextHopIP
				dstMAC, err := getRemoteMAC(ps.params.iface, nextHopIp, ps.config.arpRequestTimeout)
				if err != nil {
					log.Println("pcapSession.handleOutgoingPackets: failed to retrieve remote mac address:", err)
					continue
				}

				// construct ethernet layer
				ethernetLayer := &layers.Ethernet{
					SrcMAC:       ps.params.iface.HardwareAddr,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv4,
				}

				// Serialize the full packet including Ethernet layer
				buffer = gopacket.NewSerializeBuffer()
				err = gopacket.SerializeLayers(buffer, options, ethernetLayer, gopacket.Payload((*pkt).Data()))
				if err != nil {
					log.Println("Error serializing packet:", err)
					continue
				}
			}

			// Write the raw packet data to the pcap handle
			if err := ps.params.handle.WritePacketData(buffer.Bytes()); err != nil {
				log.Println("Error writing packet:", err)
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

	var ipConns []*RawIPConn
	ps.rawIPConnMap.Range(func(key, value interface{}) bool {
		ipConns = append(ipConns, value.(*RawIPConn))
		return true // continue iteration
	})

	for _, ipConn := range ipConns {
		ipConn.Close()
	}

	close(ps.stopChan)

	ps.wg.Wait()

	close(ps.outgoingPackets)
	ps.params.handle.Close()

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
