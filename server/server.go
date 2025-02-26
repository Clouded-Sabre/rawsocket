//go:build linux
// +build linux

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Config struct {
	IP       net.IP
	Protocol string
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

	return &Config{
		IP:       listenIP,
		Protocol: *protocol,
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
	listener, err := net.ListenIP("ip4:"+config.Protocol, &net.IPAddr{IP: config.IP})
	if err != nil {
		log.Fatalf("Failed to listen on IP %s: %v", config.IP, err)
	}
	defer listener.Close()

	fmt.Printf("Server listening on %s:%s\n", config.IP, config.Protocol)

	wg := sync.WaitGroup{}
	stopChan := make(chan struct{})
	outputChan := make(chan *packetVector)

	wg.Add(1)
	go receivePackets(listener, outputChan, stopChan, config, &wg)

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

func sendPacket(conn *net.IPConn, dstIP net.IP, message []byte, config *Config, originalPacket []byte) {
	//fmt.Printf("originalPacketByteSlice length: %d\n", len(originalPacket))
	switch config.Protocol {
	case "udp":
		sendUDPPacket(conn, dstIP, message, originalPacket)
	case "tcp":
		sendTCPPacket(conn, dstIP, message, originalPacket)
	case "icmp":
		sendICMPPacket(conn, dstIP, message)
	default:
		log.Fatalf("Unsupported protocol: %v", config.Protocol)
	}
}

func sendUDPPacket(conn *net.IPConn, dstIP net.IP, message []byte, originalPacket []byte) {
	// Reverse source and destination ports (first 4 bytes after the IP header)
	srcPort := uint16(originalPacket[0])<<8 | uint16(originalPacket[1])
	dstPort := uint16(originalPacket[2])<<8 | uint16(originalPacket[3])

	// Swap ports
	udpHeader := make([]byte, 8)
	udpHeader[0] = byte(dstPort >> 8)
	udpHeader[1] = byte(dstPort & 0xFF)
	udpHeader[2] = byte(srcPort >> 8)
	udpHeader[3] = byte(srcPort & 0xFF)

	// Set the UDP length (header length 8 bytes + payload length)
	udpLength := uint16(8 + len(message))
	udpHeader[4] = byte(udpLength >> 8)
	udpHeader[5] = byte(udpLength & 0xFF)

	// Optionally set the checksum to 0 (this would need to be computed in real use)
	udpHeader[6] = 0
	udpHeader[7] = 0

	// Pseudo-header for checksum calculation
	pseudoHeader := make([]byte, 12)
	// Get the source IP from the conn's LocalAddr() method
	localAddr := conn.LocalAddr().(*net.IPAddr) // cast to *net.IPAddr
	copy(pseudoHeader[0:4], localAddr.IP.To4()) // Source IP from the listening IP

	// Destination IP (4 bytes)
	copy(pseudoHeader[4:8], dstIP.To4()) // Destination IP
	// Reserved (1 byte), Protocol (1 byte), UDP Length (2 bytes)
	pseudoHeader[8] = 0  // Reserved byte
	pseudoHeader[9] = 17 // Protocol (17 for UDP)
	binary.BigEndian.PutUint16(pseudoHeader[10:12], udpLength)

	// Concatenate pseudo-header, UDP header, and data for checksum calculation
	dataForChecksum := append(pseudoHeader, udpHeader...)
	dataForChecksum = append(dataForChecksum, message...)

	// Calculate the checksum
	checksum := CalculateChecksum(dataForChecksum)

	// Set the checksum in the UDP header
	udpHeader[6] = byte(checksum >> 8)
	udpHeader[7] = byte(checksum & 0xFF)

	// Send the UDP packet (skip checksum calculation)
	_, err := conn.WriteTo(append(udpHeader, message...), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send UDP packet: %v", err)
	}
}

func sendTCPPacket(conn *net.IPConn, dstIP net.IP, message []byte, originalPacket []byte) {
	// Reverse source and destination ports (first 4 bytes after the IP header)
	srcPort := uint16(originalPacket[0])<<8 | uint16(originalPacket[1])
	dstPort := uint16(originalPacket[2])<<8 | uint16(originalPacket[3])

	// Swap ports
	tcpHeader := make([]byte, 20)
	tcpHeader[0] = byte(dstPort >> 8)
	tcpHeader[1] = byte(dstPort & 0xFF)
	tcpHeader[2] = byte(srcPort >> 8)
	tcpHeader[3] = byte(srcPort & 0xFF)

	// Send the TCP packet (skip checksum calculation)
	_, err := conn.WriteTo(append(tcpHeader, message...), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send TCP packet: %v", err)
	}
}

func sendICMPPacket(conn *net.IPConn, dstIP net.IP, message []byte) {
	icmpHeader := make([]byte, 8)
	_, err := conn.WriteTo(append(icmpHeader, message...), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send ICMP packet: %v", err)
	}
}

func receivePackets(conn *net.IPConn, outputChan chan *packetVector, stopChan chan struct{}, config *Config, wg *sync.WaitGroup) {
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
				go handleIncomingPackets(cl, outputChan, stopChan, config, wg)
			}
			mu.Unlock()

			// Send the received packet to the client input channel for processing
			cl.inputChan <- buffer[:n]
		}
	}
}

func handleIncomingPackets(client *client, outputChan chan *packetVector, stopChan chan struct{}, config *Config, wg *sync.WaitGroup) {
	defer wg.Done()

	// Handle the loop to continuously process packets for the client
	for {
		select {
		case <-stopChan:
			log.Printf("handleIncomingPackets from %s got stop signal. Exiting...\n", client.IP.String())
			return
		case l4packetByteSlice := <-client.inputChan:
			// Print the client IP address
			fmt.Printf("Received packet from client IP: %s\n", client.IP.String())

			// Print the protocol type (TCP/UDP/ICMP)
			fmt.Printf("Protocol type: %s\n", config.Protocol)

			// Parse the L4 packet (TCP/UDP) to extract port information and payload
			if config.Protocol == "tcp" || config.Protocol == "udp" {
				// Extract the source and destination ports (first 4 bytes after the IP header)
				var srcPort, dstPort uint16
				srcPort = uint16(l4packetByteSlice[0])<<8 | uint16(l4packetByteSlice[1])
				dstPort = uint16(l4packetByteSlice[2])<<8 | uint16(l4packetByteSlice[3])

				// Print the source and destination ports
				fmt.Printf("Source Port: %d, Destination Port: %d\n", srcPort, dstPort)

				// Extract the payload (skipping the TCP/UDP headers)
				payload := l4packetByteSlice[8:] // For UDP/TCP, the header is at least 8 bytes
				if config.Protocol == "tcp" {
					// TCP headers are usually 20 bytes; we can skip them
					payload = l4packetByteSlice[20:]
				}

				// Print only the payload content (ASCII representation for simplicity)
				fmt.Printf("Payload: %s\n", string(payload))
			}

			// Echo back the packet (to the client)
			pv := &packetVector{
				packetByteSlice: l4packetByteSlice,
				destIP:          client.IP,
				client:          client,
			}

			client.count++
			outputChan <- pv
		}
	}
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
			message := fmt.Sprintf("packet echo Seq %d", pv.client.count)

			//fmt.Printf("Sending message: %s\n", message)
			fmt.Printf("pv.packetByteSlice length: %d\n", len(pv.packetByteSlice))

			// Send the packet using net.IPConn's WriteTo method
			sendPacket(conn, pv.destIP, []byte(message), config, pv.packetByteSlice)
			log.Printf("packet %d to %s Sent.\n", pv.client.count, pv.client.IP)
		}
	}
}

func CalculateChecksum(buffer []byte) uint16 {
	var cksum uint32 = 0

	// Process 16-bit words (2 bytes each)
	for i := 0; i < len(buffer)-1; i += 2 {
		word := binary.BigEndian.Uint16(buffer[i : i+2])
		cksum += uint32(word)
	}

	// Handle remaining odd byte, if any
	if len(buffer)%2 != 0 {
		cksum += uint32(buffer[len(buffer)-1]) << 8 // Shift last byte to 16 bits
	}

	// Fold 32-bit sum to 16 bits
	cksum = (cksum >> 16) + (cksum & 0xffff)
	cksum += (cksum >> 16)

	// Return one's complement of the final sum
	return ^uint16(cksum)
}
