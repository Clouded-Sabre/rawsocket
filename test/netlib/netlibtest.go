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
	IP                net.IP
	Protocol          layers.IPProtocol
	ARPRequestTimeout int
	ARPCacheTimeout   int
}

type TCPConnection struct {
	InitialSeq     uint32
	InitialPeerSeq uint32
	NextSeq        uint32
	LastAck        uint32
	rawIPConn      *rawsocket.RawIPConn
}

var (
	connectionMap = sync.Map{} // Concurrent map to store TCP connections
)

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

func main() {
	config := parseArgs()
	if config == nil {
		return
	}

	core := rawsocket.NewRawSocketCore(config.ARPCacheTimeout, config.ARPRequestTimeout, true)

	// Listen for incoming raw connections
	rawListener, err := core.ListenIP(config.IP, config.Protocol)
	if err != nil {
		log.Fatalf("Failed to listen on IP %s: %v", config.IP, err)
	}
	defer rawListener.Close()

	// Listen for standard TCP connections
	tcpListener, err := net.Listen("tcp", config.IP.String()+":54321")
	if err != nil {
		log.Fatalf("Failed to listen on TCP port 54321: %v", err)
	}
	defer tcpListener.Close()

	fmt.Printf("Server listening on %s:54321 with protocol %s\n", config.IP.String(), config.Protocol)

	wg := sync.WaitGroup{}
	stopChan := make(chan struct{})

	// Start raw packet capture and handling
	wg.Add(1)
	go handleRawPackets(rawListener, config, stopChan, &wg)

	// Start accepting standard TCP connections
	wg.Add(1)
	go handleTCPConnections(tcpListener, stopChan, &wg)

	wg.Wait()
}

func handleRawPackets(conn *rawsocket.RawIPConn, config *Config, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	buffer := make([]byte, 1024)
	for {
		select {
		case <-stopChan:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Error reading raw packet: %v", err)
				return
			}

			log.Println("got packet!!!")
			packet := gopacket.NewPacket(buffer[:n], config.Protocol, gopacket.Default)
			processRawPacket(conn, &packet, &addr)
		}
	}
}

func processRawPacket(conn *rawsocket.RawIPConn, packet *gopacket.Packet, addr *net.Addr) {
	log.Println("begin handling packet!!!")

	// Extract TCP layer
	if tcpLayer := (*packet).Layer(layers.LayerTypeTCP); tcpLayer != nil {
		log.Println("packet has TCP layer!!!")
		tcp, _ := tcpLayer.(*layers.TCP)
		key := fmt.Sprintf("%s:%d", (*addr).String(), tcp.SrcPort)
		log.Println("Key of the packet is", key)

		// Check for SYN or SYN-ACK
		if tcp.SYN {
			log.Println("Got new connection 3-way handshake")
			if !tcp.ACK {
				log.Println("Got new connection request")
				// SYN packet (initial connection attempt)
				connectionMap.Store(key, &TCPConnection{InitialPeerSeq: tcp.Seq, InitialSeq: 0, rawIPConn: conn})
				fmt.Printf("Captured SYN packet: SrcPort=%v, Seq=%v\n", tcp.SrcPort, tcp.Seq)
			}
		} else if value, ok := connectionMap.Load(key); ok {
			connInfo := value.(*TCPConnection)
			if len(tcp.Payload) > 0 {
				fmt.Printf("Received data packet: SrcPort=%v, Seq=%v, Ack=%v, PayloadLen=%d\n",
					tcp.SrcPort, tcp.Seq, tcp.Ack, len(tcp.Payload))
				// Echo the payload back to the client
				echoPayload(connInfo, tcp, addr, tcp.Payload)
				connInfo.LastAck += uint32(len(tcp.Payload))
			} else if tcp.ACK && tcp.Seq == connInfo.InitialPeerSeq+1 {
				connInfo.InitialSeq = tcp.Ack - 1
				connInfo.NextSeq = tcp.Ack
				connInfo.LastAck = tcp.Seq
				connectionMap.Store(key, connInfo)
				fmt.Printf("Captured ACK packet: SrcPort=%v, Seq=%v, Ack=%v\n", tcp.SrcPort, tcp.Seq, tcp.Ack)
			}
		} else {
			log.Println("The packet is not destined to a port we are listening.")
		}
	}
}

func echoPayload(connInfo *TCPConnection, tcp *layers.TCP, addr *net.Addr, payload []byte) {
	// Construct the TCP packet with the same payload and headers

	// Construct the echoed TCP layer
	echoTCP := &layers.TCP{
		SrcPort:    tcp.DstPort,
		DstPort:    tcp.SrcPort,
		Seq:        connInfo.NextSeq,
		Ack:        connInfo.LastAck,
		DataOffset: 5, // Default TCP header length without options
		SYN:        false,
		ACK:        true,
		PSH:        tcp.PSH,
		Window:     1500, // Example window size
	}
	echoTCP.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP: connInfo.rawIPConn.LocalIP(),
		DstIP: (*addr).(*net.IPAddr).IP,
	})

	// Prepare the buffer for the packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Serialize the packet
	gopacket.SerializeLayers(buffer, opts,
		echoTCP,
		gopacket.Payload(payload),
	)

	// Send the packet (you'll need a raw socket or a similar method)
	log.Println("Echoing back packet...")
	connInfo.rawIPConn.WriteTo(buffer.Bytes(), *addr)
	log.Println("Echo packet sent.")
	connInfo.NextSeq += uint32(len(payload))
}

func handleTCPConnections(listener net.Listener, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-stopChan:
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Error accepting connection: %v", err)
				return
			}

			go handleTCPConnection(conn, stopChan, wg)
		}
	}
}

func handleTCPConnection(conn net.Conn, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	time.Sleep(200 * time.Millisecond)
	remoteAddr := conn.RemoteAddr().String()
	fmt.Println("New standard TCP connection established from", remoteAddr)

	// Notify RawIPConn or handle accordingly
	key := connectionMapKey(remoteAddr)
	if value, ok := connectionMap.Load(key); ok {
		connInfo := value.(*TCPConnection)
		fmt.Printf("Found initial SEQ: %d, Peer SEQ: %d for connection %s\n", connInfo.InitialSeq, connInfo.InitialPeerSeq, key)
		// Further handling...
	} else {
		fmt.Printf("No initial SEQ/Peer SEQ found for connection %s\n", key)
	}

	// Keep the connection open by continuously reading from it
	buffer := make([]byte, 4096) // Adjust the buffer size as needed
	for {
		select {
		case <-stopChan:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, err := conn.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				} else if err == io.EOF {
					// Connection closed by the peer
					fmt.Println("Connection closed by peer")
				} else {
					// Other errors
					fmt.Printf("Error reading from connection: %v\n", err)
				}
				return
			}
		}
		// Optionally log or process the read data here, if needed
	}
}

func connectionMapKey(remoteAddr string) string {
	// Extract the IP and port from the remoteAddr
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		log.Printf("Invalid remote address: %v", remoteAddr)
		return ""
	}
	return fmt.Sprintf("%s:%s", host, port)
}
