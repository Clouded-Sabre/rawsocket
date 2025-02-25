//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	rawsocket "github.com/Clouded-Sabre/rawsocket/lib"
)

var destIP string

func init() {
	// Define CLI flags for server IP and port
	flag.StringVar(&destIP, "destIP", "", "Destination IP address")
	flag.Parse()
}

func main() {
	if destIP == "" {
		fmt.Println("Please provide a destination IP address using the -destIP flag")
		os.Exit(1)
	}

	// Replace with your target destination IP
	targetIP := net.ParseIP(destIP)

	localIP, iface, gatewayIP, err := rawsocket.GetLocalIP(targetIP)
	if err != nil {
		fmt.Printf("Error finding local IP: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Local IP for routing to %s: %s\n", targetIP, localIP)
	if iface != nil {
		fmt.Println("The associated local interface for sending/receiving packet is", iface.Name)
	}
	if gatewayIP != nil {
		fmt.Printf("Since target IP is not in the same subnet as any of local IP, we will send packet to our default gateway IP %s first\n", gatewayIP.String())
	}
}
