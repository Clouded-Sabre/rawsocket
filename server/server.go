//go:build linux
// +build linux

package main

import (
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

func sendPacket(conn *net.IPConn, dstIP net.IP, message []byte, config *Config) {
	// Respond to any incoming packet regardless of the source port
	switch config.Protocol {
	case "udp":
		sendUDPPacket(conn, dstIP, message)
	case "tcp":
		sendTCPPacket(conn, dstIP, message)
	case "icmp":
		sendICMPPacket(conn, dstIP, message)
	default:
		log.Fatalf("Unsupported protocol: %v", config.Protocol)
	}
}

func sendUDPPacket(conn *net.IPConn, dstIP net.IP, message []byte) {
	// Manually construct the UDP packet and send it
	udpHeader := make([]byte, 8) // UDP header (8 bytes: 2 * 2-byte ports, 2 * 2-byte length, checksum)
	// Here you would manually set the UDP header fields (SrcPort, DstPort, Length, Checksum)
	// For responding to any port, you could use the source port of the incoming packet

	// Send the UDP packet (skip checksum calculation)
	_, err := conn.WriteTo(append(udpHeader, message...), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send UDP packet: %v", err)
	}
}

func sendTCPPacket(conn *net.IPConn, dstIP net.IP, message []byte) {
	// Manually construct the TCP packet and send it
	tcpHeader := make([]byte, 20) // TCP header (minimum 20 bytes)
	// Here you would manually set the TCP header fields (SrcPort, DstPort, Seq, Ack, Flags, etc.)
	// For responding to any port, you could use the source port of the incoming packet

	// Send the TCP packet (skip checksum calculation)
	_, err := conn.WriteTo(append(tcpHeader, message...), &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Failed to send TCP packet: %v", err)
	}
}

func sendICMPPacket(conn *net.IPConn, dstIP net.IP, message []byte) {
	// Manually construct the ICMP packet and send it
	icmpHeader := make([]byte, 8) // ICMP header (8 bytes: Type, Code, Checksum, etc.)
	// Here you would manually set the ICMP header fields (Type, Code, Checksum, etc.)

	// Send the ICMP packet (skip checksum calculation)
	_, err := conn.WriteTo(append(icmpHeader, message...), &net.IPAddr{IP: dstIP})
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
		// You can manually handle packet decoding if needed, otherwise, echo back the message
		fmt.Printf("Received packet from %s: %s\n", client.IP.String(), string(l4packetByteSlice))

		// Echo back
		pv := &packetVector{
			packetByteSlice: l4packetByteSlice,
			destIP:          client.IP,
			client:          client,
		}

		client.count++
		outputChan <- pv
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
			message := fmt.Sprintf("packet echo Seq %d: %s", pv.client.count, pv.packetByteSlice)

			// Send the packet using net.IPConn's WriteTo method
			sendPacket(conn, pv.destIP, []byte(message), config)
			log.Printf("packet %d to %s Sent.\n", pv.client.count, pv.client.IP)
		}
	}
}
