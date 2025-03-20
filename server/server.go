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
	srcPort = 54321
	dstPort = 12345
)

type Config struct {
	IP                net.IP
	Protocol          layers.IPProtocol
	ARPRequestTimeout int
	ARPCacheTimeout   int
}

func parseArgs() *Config {
	ip := flag.String("ip", "", "IP address to listen on (server) or connect to (client)")
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

	// Convert protocol to layers.IPProtocol
	ipProtocol, err := stringToIPProtocol(*protocol)
	if err != nil {
		return nil
	}

	return &Config{
		IP:                listenIP,
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
	serverPort := srcPort // fixed port for now, can be passed via config if needed
	if config.Protocol == layers.IPProtocolTCP {
		listener, err := setupTcpServer(config.IP.String(), serverPort)
		if err != nil {
			log.Fatalf("Error setting up server: %v", err)
		}
		defer listener.Close()

		// Keep the server running, but do not accept any connections
		fmt.Printf("Server is listening on port %d but not accepting connections\n", serverPort)
	}

	fmt.Printf("Server listening on %s:%s\n", config.IP, config.Protocol)

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

func sendPacket(conn *rawsocket.RawConnection, dstIP net.IP, n int, message []byte, config *Config) {
	switch config.Protocol {
	case layers.IPProtocolUDP:
		sendUDPPacket(conn, dstIP, message)
	case layers.IPProtocolTCP:
		sendTCPPacket(conn, dstIP, n, message)
	case layers.IPProtocolICMPv4:
		sendICMPPacket(conn, dstIP, message)
	default:
		log.Fatalf("Unsupported protocol: %v", config.Protocol)
	}
}

func sendUDPPacket(conn *rawsocket.RawConnection, dstIP net.IP, message []byte) {
	// Create the UDP layer
	udpLayer := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
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

func sendTCPPacket(conn *rawsocket.RawConnection, dstIP net.IP, seq int, message []byte) {
	tcpLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     uint32(seq + 1),
		Window:  1500,
		// Setting SYN, ACK, PSH, etc., flags as necessary
		// For example, if this is a simple data packet:
		PSH: true,
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

	// Set the network layer for checksum calculation.
	// Use the local IP from the connection and the destination IP.
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
}

func newClient(IP net.IP) (*client, error) {
	newclient := &client{
		IP:        IP,
		inputChan: make(chan []byte),
	}
	return newclient, nil
}

func receivePackets(conn *rawsocket.RawConnection, config *Config, outputChan chan *packetVector, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	buffer := make([]byte, 1024)
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
			// Extract the L4 payload
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
			sendPacket(conn, pv.destIP, pv.client.count, []byte(message), config)
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
