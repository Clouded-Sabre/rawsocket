//go:build windows
// +build windows

package main

import (
	"errors"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	divert "github.com/imgk/divert-go"
)

// Global variables for managing filter state
var (
	handle    *divert.Handle // WinDivert handle
	stopChan  chan struct{}  // Channel to signal stopping the filter loop
	isRunning bool           // Flag to indicate whether the filter is running
	mutex     sync.Mutex     // Ensure thread safety
)

// applyFilteringRules applies filtering rules
func applyFilteringRules(srcAddr, dstAddr net.IP, srcPort, dstPort int) error {
	mutex.Lock()
	defer mutex.Unlock()

	if isRunning {
		return errors.New("filtering rules are already applied, If you want to restart it, please call removeFilteringRules first")
	}

	// Initialize filtering rules
	filter := "tcp.Rst" // Capture all TCP RST packets
	h, err := divert.Open(filter, divert.LayerNetwork, 0, 0)
	if err != nil {
		return err
	}

	// Set global state
	handle = h
	stopChan = make(chan struct{})
	isRunning = true

	// Start filtering goroutine
	go func() {
		defer func() {
			mutex.Lock()
			defer mutex.Unlock()
			handle.Close()
			isRunning = false
		}()

		buf := make([]byte, 1500) // Packet buffer
		addr := divert.Address{}  // To store packet address
		for {
			select {
			case <-stopChan:
				log.Println("Stopping filter...")
				return
			default:
				// Receive packet
				n, err := handle.Recv(buf, &addr)
				if err != nil {
					log.Println("Failed to receive packet:", err)
					continue
				}

				// Parse packet using gopacket
				packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
				if packet == nil {
					log.Println("Failed to parse packet")
					continue
				}

				// Parse IPv4 layer
				ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
				if ipv4Layer == nil {
					log.Println("IPv4 layer not found")
					continue
				}
				ipv4, _ := ipv4Layer.(*layers.IPv4)

				// Parse TCP layer
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					log.Println("TCP layer not found")
					continue
				}
				tcp, _ := tcpLayer.(*layers.TCP)

				/*
					// Double-check: Explicitly check RST flag
					if !tcp.RST {
						log.Printf("Warning: Captured a non-RST packet (possible filter error), reinjecting")
						handle.Send(buf[:n], &addr)
						continue
					}
				*/

				// Check if the packet matches the criteria
				srcIP := ipv4.SrcIP
				dstIP := ipv4.DstIP
				sPort := int(tcp.SrcPort)
				dPort := int(tcp.DstPort)

				if srcIP.Equal(srcAddr) && sPort == srcPort &&
					dstIP.Equal(dstAddr) && dPort == dstPort {
					log.Printf("Dropping RST packet: %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
					continue // Drop directly, do not reinject
				}

				// Reinject other matching RST packets
				if _, err := handle.Send(buf[:n], &addr); err != nil {
					log.Println("Failed to reinject packet:", err)
				}
			}
		}
	}()

	log.Println("Filtering rules applied")
	return nil
}

func removeFilteringRules() error {
	mutex.Lock()
	defer mutex.Unlock()

	if !isRunning {
		return errors.New("no active filtering rules")
	}

	// Send stop signal
	close(stopChan)
	isRunning = false
	return nil
}
