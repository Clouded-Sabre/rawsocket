//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package lib

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// getRemoteMAC sends an ARP request to get the MAC address for a given IP and interface
func getRemoteMAC(iface *net.Interface, ip net.IP, arpRequestTimeout time.Duration, arpCache *ARPCache, ps *pcapSession) (net.HardwareAddr, error) {
	if Debug {
		log.Printf("getRemoteMAC: Getting remote MAC address for ip %s...\n", ip)
	}
	// Check ARP cache first
	if mac, found := arpCache.Lookup(ip.String()); found {
		return mac, nil
	}

	// Send ARP request
	if err := writeARP(ps, iface, ip); err != nil {
		return nil, fmt.Errorf("getRemoteMAC: failed to send ARP request: %w", err)
	}

	// Periodically check ARP cache for result
	ticker := time.NewTicker(50 * time.Millisecond) // Check every 50ms
	defer ticker.Stop()

	timeout := time.After(arpRequestTimeout)

	// Wait for ARP reply or timeout
	for {
		select {
		case <-ticker.C:
			if mac, found := arpCache.Lookup(ip.String()); found {
				if Debug {
					log.Printf("getRemoteMAC: Found MAC address in cache for IP %s: %s", ip, mac)
				}
				return mac, nil
			}
		case <-timeout:
			return nil, fmt.Errorf("getRemoteMAC: timeout waiting for ARP reply for IP %s", ip)
		}
	}
}

// writeARP writes an ARP request for the target IP to the pcap handle.
func writeARP(ps *pcapSession, iface *net.Interface, targetIP net.IP) error {
	// Get the interface IP address
	if Debug {
		log.Printf("iface name is: %s     target IP: %s", iface.Name, targetIP)
	}

	var ifaceIP net.IP
	if addrs, err := iface.Addrs(); err == nil {
		for _, addr := range addrs {
			if Debug {
				log.Println("addr: ", addr)
			}
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.Contains(targetIP) {
					if ip4 := ipnet.IP.To4(); ip4 != nil {
						ifaceIP = ip4
						break
					}
				}
			}
		}
	}

	if ifaceIP == nil {
		return errors.New("interface has no IPv4 address which is in the same subnet as that of target IP")
	}

	// Construct the ARP packet
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(ifaceIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP.To4()),
	}

	// Set up buffer and options for serialization
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Serialize and send the ARP packet
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}

	ps.writeMu.Lock()
	err := ps.handle.WritePacketData(buf.Bytes())
	ps.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to write ARP packet: %w", err)
	}
	if Debug {
		log.Println("ARP request sent successfully")
	}
	return nil
}

// getPcapDeviceName gets the appropriate pcap device name for the interface
func getPcapDeviceName(iface *net.Interface) string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("failed to list devices: %v", err)
	}

	// Get the IP addresses of the interface
	var ifaceIPs []net.IP
	if addrs, err := iface.Addrs(); err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ifaceIPs = append(ifaceIPs, ip4)
				}
			}
		}
	}
	if Debug {
		log.Printf("interface %s's ip list: %+v", iface.Name, ifaceIPs)
	}

	for _, device := range devices {
		for _, address := range device.Addresses {
			ip := address.IP.To4()
			if ip != nil {
				if Debug {
					log.Printf("Pcap device %s ip: %s\n", device.Name, ip)
				}
				for _, ifaceIP := range ifaceIPs {
					if ifaceIP.String() == ip.String() {
						return device.Name
					}
				}
			}
		}
	}
	log.Fatalf("No matching device found for interface: %v", iface.Name)
	return ""
}

// listInterfaces prints the available network interfaces
func ListInterfaces() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	log.Println("Available Network Interfaces:")
	for _, iface := range ifaces {
		fmt.Printf("Name: %v, HardwareAddr: %v\n", iface.Name, iface.HardwareAddr)
	}
	return nil
}
