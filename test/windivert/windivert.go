//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	divert "github.com/imgk/divert-go"
)

// Helper to check if TCP packet has RST flag set.
func isRSTPacket(packet []byte) bool {
	packetDecoded := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
	tcpLayer := packetDecoded.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	return tcp.RST
}

func main() {
	filter := "outbound and tcp"
	handle, err := divert.Open(filter, divert.LayerNetwork, 0, 0)
	if err != nil {
		log.Fatalf("Failed to open WinDivert handle: %v", err)
	}
	defer handle.Close()

	packet := make([]byte, 1500)
	var addr divert.Address

	fmt.Println("Start capturing outbound TCP packets (dropping RST packets)...")

	for {
		n, err := handle.Recv(packet, &addr)
		if err != nil {
			log.Printf("Recv failed: %v", err)
			continue
		}

		if isRSTPacket(packet[:n]) {
			fmt.Println("Dropped an outgoing RST packet!")
			continue
		}

		_, err = handle.Send(packet[:n], &addr)
		if err != nil {
			log.Printf("Send failed: %v", err)
		}
	}
}
