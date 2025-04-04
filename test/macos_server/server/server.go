// This server application uses raw sockets to listen for and respond to network packets at the IP layer.
// It supports TCP, UDP, and ICMP protocols. The server parses command-line arguments for IP address and protocol.
// It sets up a raw socket listener and, in the case of TCP, also creates a non-accepting TCP listener to prevent RST packets.
// The server receives packets, extracts the L4 payload, echoes the payload back to the client, and manages client connections using a map.
// It uses goroutines for concurrent packet handling.

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"time"

	rawsocket "github.com/Clouded-Sabre/rawsocket/lib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	// TCP Connection States
	TCP_NEW = iota
	TCP_SYN_RECEIVED
	TCP_ESTABLISHED
	TCP_CLOSING // New state for connection termination
)

var writeDstPort int
var Debug = false

type Config struct {
	IP                net.IP
	port              int
	Protocol          layers.IPProtocol
	ARPRequestTimeout int
	ARPCacheTimeout   int
}

func parseArgs() *Config {
	ip := flag.String("ip", "", "IP address to listen on")
	port := flag.Int("port", 54321, "service port to listen on")
	protocol := flag.String("protocol", "tcp", "Protocol to use (tcp/udp)")
	arpCacheTimeout := flag.Int("arpCacheTimeout", 30, "ARP cache timeout in seconds")
	arpRequestTimeout := flag.Int("arpRequestTimeout", 60, "ARP request timeout in seconds")

	flag.Parse()

	if *ip == "" {
		log.Println("Listening IP address is required")
		flag.Usage()
		return nil
	}

	listenIP := net.ParseIP(*ip)
	if listenIP == nil {
		log.Println("Listening IP address is malformed", *ip)
		return nil
	}

	listenPort := *port
	if listenPort < 0 || listenPort > 65535 {
		log.Println("Listening port must be between 0 and 65535")
		return nil
	}

	// Convert protocol to layers.IPProtocol
	ipProtocol, err := stringToIPProtocol(*protocol)
	if err != nil {
		return nil
	}

	return &Config{
		IP:                listenIP,
		port:              listenPort,
		Protocol:          ipProtocol,
		ARPRequestTimeout: *arpRequestTimeout,
		ARPCacheTimeout:   *arpCacheTimeout,
	}
}

func stringToIPProtocol(proto string) (layers.IPProtocol, error) {
	switch strings.ToLower(proto) {
	case "tcp":
		return layers.IPProtocolTCP, nil
	case "udp":
		return layers.IPProtocolUDP, nil
	case "icmp":
		return layers.IPProtocolICMPv4, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

var clientMap = make(map[string]*client)
var mu sync.Mutex

func main() {
	config := parseArgs()
	if config == nil {
		return
	}

	rsconfig := &rawsocket.RsConfig{
		ArpRequestTimeout: config.ARPRequestTimeout,
		ArpCacheTimeout:   config.ARPCacheTimeout,
	}
	// Create the RawSocketCore
	core, err := rawsocket.NewRSCore(rsconfig)
	if err != nil {
		log.Fatalf("Failed to create RawSocketCore: %v", err)
	}

	// Listen for incoming connections
	networkString, err := protocolToListenNetwork(config.IP, config.Protocol)
	if err != nil {
		log.Fatal("Network protocol string is malformed")
	}

	listener, err := core.ListenIP(networkString, &net.IPAddr{IP: config.IP})
	if err != nil {
		log.Fatalf("Failed to listen on IP %s: %v", config.IP, err)
	}
	defer listener.Close()

	// Only add tcp dumb server to avoid RST if protocol is TCP
	serverPort := config.port // fixed port for now, can be passed via config if needed
	if config.Protocol == layers.IPProtocolTCP {
		listener, err := setupTcpServer(config.IP.String(), serverPort)
		if err != nil {
			log.Fatalf("Error setting up server: %v", err)
		}
		defer listener.Close()

		// Keep the server running, but do not accept any connections
		fmt.Printf("TCP Server is listening on %s:%d but not accepting connections\n", config.IP.String(), serverPort)
	}

	fmt.Printf("%s Server listening on %s:%d\n", config.Protocol, config.IP, config.port)

	wg := sync.WaitGroup{}
	stopChan := make(chan struct{})
	outputChan := make(chan *packetVector)

	wg.Add(1)
	go receivePackets(&listener, config, outputChan, stopChan, &wg)

	wg.Add(1)
	go handleOutgoingPackets(&listener, outputChan, config, stopChan, &wg)

	wg.Wait()
}

func setupTcpServer(ip string, port int) (*net.TCPListener, error) {
	// Create a TCP socket and bind it to the desired IP address and port
	address := fmt.Sprintf("%s:%d", ip, port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener on %s: %v", address, err)
	}

	// Don't accept any connections, just call Listen()
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("failed to cast listener to TCPListener")
	}

	// This makes the kernel aware of the port and prevents RST from being sent
	tcpListener.SetDeadline(time.Now().Add(1 * time.Second)) // optional, just to make it a valid listener

	// Return the listener
	return tcpListener, nil
}

func sendPacket(conn *rawsocket.RawConnection, dstIP net.IP, message []byte, config *Config) {
	switch config.Protocol {
	case layers.IPProtocolUDP:
		sendUDPPacket(conn, dstIP, message, config)
	case layers.IPProtocolTCP:
		sendTCPPacket(conn, dstIP, message, config)
	case layers.IPProtocolICMPv4:
		sendICMPPacket(conn, dstIP, message)
	default:
		log.Fatalf("Unsupported protocol: %v", config.Protocol)
	}
}

func sendUDPPacket(conn *rawsocket.RawConnection, dstIP net.IP, message []byte, config *Config) {
	// Create the UDP layer
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(config.port),
		DstPort: layers.UDPPort(writeDstPort),
		Length:  8 + uint16(len(message)), // UDP header length + payload length
	}

	var srcIP net.IP
	switch v := (*conn).LocalAddr().(type) {
	case *net.IPAddr:
		srcIP = v.IP
	case *net.UDPAddr:
		srcIP = v.IP
	case *net.TCPAddr:
		srcIP = v.IP
	default:
		fmt.Println("unknown address type")
	}

	// Set the network layer for checksum calculation
	udpLayer.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP: srcIP,
		DstIP: dstIP,
	})

	// Serialize the UDP layer and the payload
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, udpLayer, gopacket.Payload(message))
	if err != nil {
		log.Fatalf("Failed to serialize UDP packet: %v", err)
	}

	// Send the serialized L4 packet
	_, err = (*conn).WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send UDP packet: %v", err)
	}
}

func sendTCPPacket(conn *rawsocket.RawConnection, dstIP net.IP, message []byte, config *Config) {
	srcIP := getSrcIP(conn)

	// Get client from map
	mu.Lock()
	client, exists := clientMap[dstIP.String()]
	if !exists {
		mu.Unlock()
		log.Printf("No client found for IP %s\n", dstIP)
		return
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(config.port),
		DstPort: layers.TCPPort(writeDstPort),
		Seq:     client.nextSeq,
		Ack:     client.nextAck,
		Window:  1500,
		ACK:     true,
		PSH:     true,
	}

	client.nextSeq += uint32(len(message))
	mu.Unlock()

	// Set the network layer for checksum calculation.
	tcpLayer.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP: srcIP,
		DstIP: dstIP,
	})

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, tcpLayer, gopacket.Payload(message))
	if err != nil {
		log.Fatalf("Failed to serialize TCP packet: %v", err)
	}

	_, err = (*conn).WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send TCP packet: %v", err)
	}
}

func sendICMPPacket(conn *rawsocket.RawConnection, dstIP net.IP, message []byte) {
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0), // Echo request
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, icmpLayer, gopacket.Payload(message))
	if err != nil {
		log.Fatalf("Failed to serialize ICMP packet: %v", err)
	}

	_, err = (*conn).WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send ICMP packet: %v", err)
	}
}

type client struct {
	IP        net.IP
	inputChan chan []byte
	count     int
	tcpState  int
	nextSeq   uint32
	nextAck   uint32
	//theirSeq    uint32
}

func newClient(IP net.IP) (*client, error) {
	newclient := &client{
		IP:        IP,
		inputChan: make(chan []byte),
		tcpState:  TCP_NEW,
		nextSeq:   uint32(time.Now().UnixNano()), // Random initial sequence number
	}
	return newclient, nil
}

func receivePackets(conn *rawsocket.RawConnection, config *Config, outputChan chan *packetVector, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	buffer := make([]byte, 4096)
	for {
		select {
		case <-stopChan:
			log.Println("receivePackets got stop signal. Exitting...")
			return
		default:
			(*conn).SetReadDeadline(time.Now().Add(500 * time.Millisecond)) // read wait for 500 ms
			n, addr, err := (*conn).ReadFrom(buffer)
			if err != nil {
				// Check if the error is a timeout
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Handle timeout error (no data received within the timeout period)
					continue // Continue waiting for incoming packets or handling closeSignal
				}
				if err == io.EOF {
					log.Println("Server app got interruption. Stop and exit.")
					return
				}
				fmt.Println("Error reading packet:", err)
				return
			}

			// First check if this packet is for our service
			var dstPort int
			if config.Protocol == layers.IPProtocolTCP {
				tcpLayer := &layers.TCP{}
				err := tcpLayer.DecodeFromBytes(buffer[:n], gopacket.NilDecodeFeedback)
				if err != nil {
					fmt.Println("Error decoding TCP layer:", err)
					continue
				}
				dstPort = int(tcpLayer.DstPort)
			} else if config.Protocol == layers.IPProtocolUDP {
				udpLayer := &layers.UDP{}
				err := udpLayer.DecodeFromBytes(buffer[:n], gopacket.NilDecodeFeedback)
				if err != nil {
					fmt.Println("Error decoding UDP layer:", err)
					continue
				}
				dstPort = int(udpLayer.DstPort)
			}

			// Verify this packet is for our service
			if dstPort != config.port {
				if Debug {
					log.Printf("Ignoring packet: wrong destination port. Expected %d, got %d\n", config.port, dstPort)
				}
				continue
			}

			srcIP := addr.String()
			mu.Lock()
			cl, exists := clientMap[srcIP]
			if !exists {
				cl, _ = newClient(net.ParseIP(srcIP))
				clientMap[srcIP] = cl
				wg.Add(1)
				go handleIncomingPackets(cl, config, outputChan, stopChan, wg)
			}
			mu.Unlock()

			// Determine the transport layer protocol and update dstPort accordingly
			if config.Protocol == layers.IPProtocolTCP {
				//log.Println("Received TCP packet from", srcIP, "with length", n)
				tcpLayer := &layers.TCP{}
				err := tcpLayer.DecodeFromBytes(buffer[:n], gopacket.NilDecodeFeedback)
				if err != nil {
					fmt.Println("Error decoding TCP layer:", err)
					continue
				}
				writeDstPort = int(tcpLayer.SrcPort) // Update dstPort with the TCP source port
			} else if config.Protocol == layers.IPProtocolUDP {
				udpLayer := &layers.UDP{}
				err := udpLayer.DecodeFromBytes(buffer[:n], gopacket.NilDecodeFeedback)
				if err != nil {
					fmt.Println("Error decoding UDP layer:", err)
					continue
				}
				writeDstPort = int(udpLayer.SrcPort) // Update dstPort with the UDP source port
			}

			cl.inputChan <- buffer[:n]
		}

	}
}

type packetVector struct {
	packetByteSlice []byte
	destIP          net.IP
	client          *client
}

func handleIncomingPackets(client *client, config *Config, outputChan chan *packetVector, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-stopChan:
			log.Printf("handleIncomingPackets from %s got stop signal. Exiting...\n", client.IP.String())
			return
		case l4packetByteSlice := <-client.inputChan:
			if config.Protocol == layers.IPProtocolTCP {
				packet := gopacket.NewPacket(l4packetByteSlice, layers.LayerTypeTCP, gopacket.Default)
				tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

				// First check if this is a connection termination packet
				if tcpLayer.FIN || tcpLayer.RST {
					if client.tcpState != TCP_CLOSING {
						log.Printf("Connection termination detected from %s, letting kernel handle it\n", client.IP)
						client.tcpState = TCP_CLOSING
					}
					continue // Ignore this packet and all subsequent packets
				}

				// If we're in CLOSING state, ignore all packets
				if client.tcpState == TCP_CLOSING {
					continue
				}

				switch client.tcpState {
				case TCP_NEW:
					if tcpLayer.SYN {
						// Received SYN, the kernel will send SYN-ACK
						//client.theirSeq = tcpLayer.Seq
						client.nextAck = tcpLayer.Seq + 1
						client.tcpState = TCP_SYN_RECEIVED
						log.Printf("Received SYN from %s:%d, seq=%d\n", client.IP, tcpLayer.SrcPort, tcpLayer.Seq)
					}
				case TCP_SYN_RECEIVED:
					if tcpLayer.ACK {
						// Received final ACK of 3-way handshake
						client.tcpState = TCP_ESTABLISHED
						client.nextSeq = tcpLayer.Ack
						log.Printf("Connection established with %s:%d, ack=%d\n", client.IP, tcpLayer.SrcPort, tcpLayer.Ack)
					}
				case TCP_ESTABLISHED:
					if len(tcpLayer.Payload) > 0 {
						// Normal data packet
						//client.nextSeq = tcpLayer.Seq

						client.nextAck = tcpLayer.Seq + uint32(len(tcpLayer.Payload))
						log.Printf("Connection got data packet from %s:%d, len=%d\n", client.IP, tcpLayer.SrcPort, len(tcpLayer.Payload))
						pv := &packetVector{
							packetByteSlice: tcpLayer.Payload,
							destIP:          client.IP,
							client:          client,
						}
						client.count++
						outputChan <- pv
					}
				}
			} else {
				// Handle non-TCP protocols as before
				payload := getL4Payload(l4packetByteSlice, config.Protocol)
				if payload != nil {
					fmt.Printf("Received packet from %s: %s\n", client.IP.String(), string(payload))
				} else {
					fmt.Println("No L4 payload found")
				}

				// echo back
				pv := &packetVector{
					packetByteSlice: payload,
					destIP:          client.IP,
					client:          client,
				}

				client.count++
				outputChan <- pv
			}
		}
	}
}

func handleOutgoingPackets(conn *rawsocket.RawConnection, outputChan chan *packetVector, config *Config, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-stopChan:
			log.Println("handleOutgoingPackets got stop signal. Exiting ... ")
			return
		case pv := <-outputChan:
			log.Printf("Sending packet %d to %s\n", pv.client.count, pv.client.IP)
			message := fmt.Sprintf("packet echo Seq %d: %s", pv.client.count, pv.packetByteSlice)
			sendPacket(conn, pv.destIP, []byte(message), config)
		}
	}

}

// getL4Payload extracts the L4 payload from the raw byte slice based on the protocol
func getL4Payload(packetData []byte, protocol layers.IPProtocol) []byte {

	// Check for the correct protocol layer and extract the payload
	switch protocol {
	case layers.IPProtocolTCP:
		// Create a new packet from the raw byte slice
		packet := gopacket.NewPacket(packetData, layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			return tcp.Payload
		}
	case layers.IPProtocolUDP:
		// Create a new packet from the raw byte slice
		packet := gopacket.NewPacket(packetData, layers.LayerTypeUDP, gopacket.Default)
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			return udp.Payload
		}
	case layers.IPProtocolICMPv4:
		// Create a new packet from the raw byte slice
		packet := gopacket.NewPacket(packetData, layers.LayerTypeICMPv4, gopacket.Default)
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			return icmp.Payload
		}
	}

	return nil
}

func protocolToListenNetwork(ip net.IP, protocol layers.IPProtocol) (string, error) {
	isIPv6 := ip.To4() == nil

	protocolMap := map[layers.IPProtocol]string{
		layers.IPProtocolICMPv4: "icmp",
		layers.IPProtocolICMPv6: "icmp",
		layers.IPProtocolTCP:    "tcp",
		layers.IPProtocolUDP:    "udp",
	}

	protoName, found := protocolMap[protocol]
	if !found {
		return "", fmt.Errorf("unsupported protocol: %d", protocol)
	}

	if isIPv6 {
		return "ip6:" + protoName, nil
	} else {
		return "ip4:" + protoName, nil
	}
}

// Helper function to get source IP
func getSrcIP(conn *rawsocket.RawConnection) net.IP {
	var srcIP net.IP
	switch v := (*conn).LocalAddr().(type) {
	case *net.IPAddr:
		srcIP = v.IP
	case *net.UDPAddr:
		srcIP = v.IP
	case *net.TCPAddr:
		srcIP = v.IP
	default:
		fmt.Println("unknown address type")
	}
	return srcIP
}
