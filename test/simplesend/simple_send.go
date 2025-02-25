//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	rawsocket "github.com/Clouded-Sabre/rawsocket/lib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	destIP, sourceIP                   string
	arpCacheTimeout, arpRequestTimeout int
)

func init() {
	// Define CLI flags for server IP and port
	flag.StringVar(&destIP, "destIP", "", "Destination IP address")
	flag.StringVar(&sourceIP, "sourceIP", "", "source IP address. Default is empty string which means let system choose appropiate local ip as source address")
	flag.IntVar(&arpCacheTimeout, "arpCacheTimeout", 120, "arp Cache table entry timeout in seconds")
	flag.IntVar(&arpRequestTimeout, "arpRequestTimeout", 60, "arp request timeout in seconds")
	flag.Parse()
}

func main() {
	// List available network interfaces
	if err := rawsocket.ListInterfaces(); err != nil {
		log.Fatalf("failed to list interfaces: %v", err)
	}

	dstIP := net.ParseIP(destIP)
	srcIP := net.ParseIP(sourceIP)
	core := rawsocket.NewRawSocketCore(arpCacheTimeout, arpRequestTimeout)
	defer core.Close()
	log.Println("Raw Socket Core started.")

	conn, err := core.DialIP(layers.IPProtocolUDP, srcIP, dstIP)
	if err != nil {
		log.Fatalf("DialIP failed: %v", err)
	}
	defer conn.Close()

	srcIP, _, _, _ = rawsocket.GetLocalIP(dstIP)
	udpLayer := &layers.UDP{
		SrcPort: 12345,
		DstPort: 54321,
		Length:  8 + 6, // UDP header length + payload length
	}
	udpLayer.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP: srcIP,
		DstIP: dstIP,
	})

	// Serialize the UDP layer and the payload
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buffer, opts, udpLayer, gopacket.Payload([]byte("Hello!")))
	if err != nil {
		log.Fatalf("Failed to serialize UDP packet: %v", err)
	}

	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	fmt.Println("Packet sent successfully")

	rbuffer := make([]byte, 65535)
	n, err := conn.Read(rbuffer)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}

	fmt.Printf("Received %d bytes: %x\n", n, rbuffer[:n])
}
