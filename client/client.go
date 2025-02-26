//go:build darwin || freebsd || windows
// +build darwin freebsd windows

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

type Config struct {
	serverIP          net.IP
	sourceIP          net.IP
	Protocol          layers.IPProtocol
	ARPRequestTimeout int
	ARPCacheTimeout   int
}

// ANSI escape codes for colors
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Reset  = "\033[0m"
)

func parseArgs() *Config {
	serverIPStr := flag.String("serverIP", "", "IP address of IPConn server")
	sourceIPStr := flag.String("sourceIP", "", "IP address of local source address")
	protocol := flag.String("protocol", "tcp", "Protocol to use (tcp/udp)")
	arpCacheTimeout := flag.Int("arpCacheTimeout", 30, "ARP cache timeout in seconds")
	arpRequestTimeout := flag.Int("arpRequestTimeout", 60, "ARP request timeout in seconds")

	flag.Parse()

	if *serverIPStr == "" {
		log.Println("server IP address is required")
		flag.Usage()
		return nil
	}

	serverIP := net.ParseIP(*serverIPStr)
	if serverIP == nil {
		log.Println("Listening IP address is malformed", *serverIPStr)
		return nil
	}

	var sourceIP net.IP
	if *sourceIPStr == "" {
		sourceIP = nil
	} else {
		sourceIP = net.ParseIP(*sourceIPStr)
		if sourceIP == nil {
			log.Println("local source IP address is malformed", *sourceIPStr)
			return nil
		}
	}

	// Convert protocol to layers.IPProtocol
	ipProtocol, err := stringToIPProtocol(*protocol)
	if err != nil {
		return nil
	}

	return &Config{
		serverIP:          serverIP,
		sourceIP:          sourceIP,
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

func main() {
	config := parseArgs()
	if config == nil {
		return
	}

	// Create the RawSocketCore
	core := rawsocket.NewRawSocketCore(config.ARPCacheTimeout, config.ARPRequestTimeout)

	startClient(core, config)
}

func startClient(core *rawsocket.RawSocketCore, config *Config) {
	conn, err := core.DialIP(config.Protocol, config.sourceIP, config.serverIP)
	if err != nil {
		log.Fatalf("Failed to dial to server IP %s: %v", config.serverIP, err)
	}
	defer conn.Close()

	var (
		wg       = sync.WaitGroup{}
		stopChan = make(chan struct{})
	)
	// start Handle incoming responses first to avoid possible response miss
	wg.Add(1)
	go receiveResponses(conn, stopChan, &wg)

	// Start sending packets with sequence IDs
	wg.Add(1)
	n := 10
	interval := 1000 // ms
	go sendPackets(n, interval, conn, config, &wg)

	// Start a timer to close stopChan after the specified timeout
	timeout := time.Duration(n*interval+5000) * time.Millisecond // n*interval + 5 seconds
	go func() {
		time.Sleep(timeout)
		log.Println("Timeout reached. Stopping go routines and exit.")
		close(stopChan)
	}()

	wg.Wait()
}

func sendPackets(n int, interval int, conn *rawsocket.RawIPConn, config *Config, wg *sync.WaitGroup) {
	defer wg.Done()

	intervalDuration := time.Duration(interval) * time.Millisecond
	for i := 0; i < n; i++ {
		fmt.Println(Yellow+"Sending packet", i, Reset)
		message := fmt.Sprintf("Sending packet Seq:%d", i)

		switch config.Protocol {
		case layers.IPProtocolUDP:
			sendUDPPacket(conn, config, message)
		case layers.IPProtocolTCP:
			sendTCPPacket(conn, i, config, message)
		case layers.IPProtocolICMPv4:
			sendICMPPacket(conn, message)
		default:
			log.Fatalf("Unsupported protocol: %v", config.Protocol)
		}

		fmt.Println(Yellow+"Packet", i, "sent.", Reset)

		time.Sleep(intervalDuration)
	}
}

func sendUDPPacket(conn *rawsocket.RawIPConn, config *Config, message string) {
	srcIP, _, _, _ := rawsocket.GetLocalIP(config.serverIP)
	udpLayer := &layers.UDP{
		SrcPort: 12345,
		DstPort: 54321,
		Length:  8 + uint16(len(message)), // UDP header length + payload length
	}
	udpLayer.SetNetworkLayerForChecksum(&layers.IPv4{ // needed for pseudo IP header for checksum calculation
		SrcIP: srcIP,
		DstIP: config.serverIP,
	})

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, udpLayer, gopacket.Payload([]byte(message)))
	if err != nil {
		log.Fatalf("Failed to serialize UDP packet: %v", err)
	}

	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Fatalf("Failed to send UDP packet: %v", err)
	}
}

func sendTCPPacket(conn *rawsocket.RawIPConn, seq int, config *Config, message string) {
	srcIP, _, _, _ := rawsocket.GetLocalIP(config.serverIP)
	tcpLayer := &layers.TCP{
		SrcPort: 12345,
		DstPort: 54321,
		Seq:     uint32(seq + 1),
		Window:  1500,
	}
	tcpLayer.SetNetworkLayerForChecksum(&layers.IPv4{ // needed for pseudo IP header for checksum calculation
		SrcIP: srcIP,
		DstIP: config.serverIP,
	})

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, tcpLayer, gopacket.Payload([]byte(message)))
	if err != nil {
		log.Fatalf("Failed to serialize TCP packet: %v", err)
	}

	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Fatalf("Failed to send TCP packet: %v", err)
	}
}

func sendICMPPacket(conn *rawsocket.RawIPConn, message string) {
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0), // Echo request
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, icmpLayer, gopacket.Payload([]byte(message)))
	if err != nil {
		log.Fatalf("Failed to serialize ICMP packet: %v", err)
	}

	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Fatalf("Failed to send ICMP packet: %v", err)
	}
}

func receiveResponses(conn *rawsocket.RawIPConn, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	buffer := make([]byte, 1024)
	for {
		select {
		case <-stopChan:
			log.Println("receiveResponses got stop signal. Exitting...")
			return
		default:
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) // read wait for 500 ms
			n, err := conn.Read(buffer)
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
			// Decode the packet
			packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv4, gopacket.Default)

			// Extract the L4 payload
			if payload := getL4Payload(packet); payload != nil {
				fmt.Printf("Received response: %s\n", string(payload))
			} else {
				fmt.Println("No L4 payload found")
			}
		}

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
