//go:build linux
// +build linux

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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
		IP:       listenIP,
		Protocol: ipProtocol,
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

	// Create the IPConn listener for Linux (standard Go net package)
	listener, err := net.ListenIP("ip4:"+config.Protocol.String(), &net.IPAddr{IP: config.IP})
	if err != nil {
		log.Fatalf("Failed to listen on IP %s: %v", config.IP, err)
	}
	defer listener.Close()

	fmt.Printf("Server listening on %s:%s\n", config.IP, config.Protocol)

	wg := sync.WaitGroup{}
	stopChan := make(chan struct{})
	outputChan := make(chan *packetVector)

	wg.Add(1)
	go receivePackets(listener, outputChan, stopChan, &wg)

	wg.Add(1)
	go handleOutgoingPackets(listener, outputChan, config, stopChan, &wg)

	wg.Wait()
}

type packetVector struct {
	packetByteSlice []byte
	destIP          net.IP
	client          *client
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

func sendPacket(conn *net.IPConn, dstIP net.IP, n int, message []byte, config *Config) {
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

func sendUDPPacket(conn *net.IPConn, dstIP net.IP, message []byte) {
	// Create the UDP layer
	udpLayer := &layers.UDP{
		SrcPort: 54321,
		DstPort: 12345,
		Length:  8 + uint16(len(message)), // UDP header length + payload length
	}

	// Serialize the UDP layer and the payload
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, udpLayer, gopacket.Payload(message))
	if err != nil {
		log.Fatalf("Failed to serialize UDP packet: %v", err)
	}

	// Send the serialized L4 packet
	_, err = conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send UDP packet: %v", err)
	}
}

func sendTCPPacket(conn *net.IPConn, dstIP net.IP, seq int, message []byte) {
	tcpLayer := &layers.TCP{
		SrcPort: 54321,
		DstPort: 12345,
		Seq:     uint32(seq + 1),
		Window:  1500,
		// Setting SYN, ACK, PSH, etc., flags as necessary
		// For example, if this is a simple data packet:
		PSH: true,
	}

	// Normally, you would set the network layer for checksum here if necessary.
	// Since RawIPConn handles the L3 header, we are omitting that step.

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, tcpLayer, gopacket.Payload(message))
	if err != nil {
		log.Fatalf("Failed to serialize TCP packet: %v", err)
	}

	_, err = conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send TCP packet: %v", err)
	}
}

func sendICMPPacket(conn *net.IPConn, dstIP net.IP, message []byte) {
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0), // Echo request
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, icmpLayer, gopacket.Payload(message))
	if err != nil {
		log.Fatalf("Failed to serialize ICMP packet: %v", err)
	}

	_, err = conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send ICMP packet: %v", err)
	}
}

func receivePackets(conn *net.IPConn, outputChan chan *packetVector, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	buffer := make([]byte, 1024) // Buffer to hold incoming packets
	for {
		select {
		case <-stopChan:
			log.Println("receivePackets got stop signal. Exiting...")
			return
		default:
			// Set read deadline (this is similar to SetReadDeadline with RawIPConn)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) // wait for 500ms

			n, addr, err := conn.ReadFrom(buffer) // Read raw packet from net.IPConn
			if err != nil {
				// Handle timeout errors gracefully
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout error, continue listening
					continue
				}
				if err == io.EOF {
					log.Println("Server app got interruption. Stop and exit.")
					return
				}
				log.Println("Error reading packet:", err)
				return
			}

			// Convert the source address to string
			srcIP := addr.String()

			// Find or create a new client for the source IP
			mu.Lock()
			cl, exists := clientMap[srcIP]
			if !exists {
				cl, _ = newClient(net.ParseIP(srcIP))
				clientMap[srcIP] = cl
				wg.Add(1)
				go handleIncomingPackets(cl, outputChan, stopChan, wg)
			}
			mu.Unlock()

			// Send the received packet to the client input channel for processing
			cl.inputChan <- buffer[:n]
		}
	}
}

func handleIncomingPackets(client *client, outputChan chan *packetVector, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-stopChan:
		log.Printf("handleIncomingPackets from %s got stop signal. Exiting...\n", client.IP.String())
		return
	case l4packetByteSlice := <-client.inputChan:
		// Decode the packet
		l4packet := gopacket.NewPacket(l4packetByteSlice, layers.LayerTypeIPv4, gopacket.Default)

		// Extract the L4 payload
		payload := getL4Payload(l4packet)
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

// getL4Payload extracts the L4 payload from the packet
func getL4Payload(packet gopacket.Packet) []byte {
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		return appLayer.Payload()
	}

	// Handle TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.Payload
	}

	// Handle UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return udp.Payload
	}

	// Handle ICMP layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		return icmp.Payload
	}

	return nil
}

func handleOutgoingPackets(conn *net.IPConn, outputChan chan *packetVector, config *Config, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-stopChan:
			log.Println("handleOutgoingPackets got stop signal. Exiting ... ")
			return
		case pv := <-outputChan:
			log.Printf("Sending packet %d to %s\n", pv.client.count, pv.client.IP)
			message := fmt.Sprintf("packet echo Seq %d: %s", pv.client.count, pv.packetByteSlice)

			// Send the packet using net.IPConn's WriteTo method
			sendPacket(conn, pv.destIP, pv.client.count, []byte(message), config)
		}
	}
}
