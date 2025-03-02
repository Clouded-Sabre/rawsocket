//go:build darwin || freebsd
// +build darwin freebsd

package lib

import (
	"fmt"
	"log"
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// getLocalIP finds the local IP that can route to the given destination IP
func GetLocalIP(dstIP net.IP) (net.IP, *net.Interface, net.IP, error) {
	// Handle loopback IP separately
	loIface, err := getLoopbackInterface()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot find loopback interface")
	}
	if dstIP.IsLoopback() {
		if dstIP.String() == "127.0.0.1" {
			return net.ParseIP("127.0.0.2"), loIface, nil, nil // Return a different loopback IP
		}
		return net.ParseIP("127.0.0.1"), loIface, nil, nil
	}

	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, nil, nil, err
	}

	routes, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, nil, nil, err
	}

	var bestRoute *route.RouteMessage
	bestMatchLength := 0
	//var defaultRoute *route.RouteMessage

	for _, r := range routes {
		if rtMsg, ok := r.(*route.RouteMessage); ok {
			//fmt.Printf("routeMessage: %+v\n", *rtMsg)
			destAddr := rtMsg.Addrs[syscall.RTAX_DST]
			maskAddr := rtMsg.Addrs[syscall.RTAX_NETMASK]

			destIPNet := addrToIPNet(destAddr, maskAddr)
			if destIPNet == nil {
				continue
			}

			/*if destIPNet.IP.Equal(net.IPv4zero) {
				// Track the first default route found
				if defaultRoute == nil {
					defaultRoute = rtMsg
				}
				continue
			}*/

			if destIPNet.Contains(dstIP) {
				maskSize, _ := destIPNet.Mask.Size()
				if maskSize > bestMatchLength {
					bestMatchLength = maskSize
					bestRoute = rtMsg
				}
			}
		}
	}

	var (
		chosenIP, gatewayIP net.IP
		chosenIface         *net.Interface
	)
	if bestRoute != nil {
		chosenIP, chosenIface, err = getInterfaceIP(bestRoute, dstIP)
		if err != nil {
			log.Println("Cannot find chosenIP and chosenIface:", err)
		}
		// check if best route is a default route
		subnet, err := getSubnetFromIP(chosenIface, chosenIP)
		if err != nil {
			log.Fatal("Cannot find chosenIP's subnet:", err)
		}
		if !subnet.Contains(dstIP) { // default route
			if gwAddr, ok := bestRoute.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr); ok {
				if Debug {
					fmt.Println("Gateway IP of the default route is", bestRoute.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr).IP)
				}
				gatewayIP = net.IP(gwAddr.IP[:])
			}
		}
	} else {
		return nil, nil, nil, fmt.Errorf("no suitable route found for IP %v", dstIP)
	}

	if err != nil {
		return nil, nil, nil, err
	}

	// Ensure the chosen IP is not the same as the destination IP
	if chosenIP.Equal(dstIP) { // dstIP must be a local IP
		return net.ParseIP("127.0.0.1"), loIface, nil, nil // Return a fallback IP for non-loopback cases
	}

	return chosenIP, chosenIface, gatewayIP, nil
}

// getInterfaceIP retrieves the local IP address and the network interface associated with the given route
func getInterfaceIP(rtMsg *route.RouteMessage, dstIP net.IP) (net.IP, *net.Interface, error) {
	iface, err := net.InterfaceByIndex(rtMsg.Index)
	if err != nil {
		return nil, nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}

	if Debug {
		fmt.Println("Addresses are:", addrs)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil {
				if Debug {
					fmt.Println("ipNet is:", ipNet)
				}
				var gatewayIP net.IP
				if rtMsg.Addrs[syscall.RTAX_GATEWAY] != nil {
					gatewayIP = addrToIP(rtMsg.Addrs[syscall.RTAX_GATEWAY])
				}
				if gatewayIP != nil {
					if Debug {
						fmt.Println("Gateway IP is:", gatewayIP)
					}
					if ipNet.Contains(gatewayIP) {
						return ipNet.IP, iface, nil
					}
				} else {
					if Debug {
						fmt.Println("dstIP:", dstIP)
					}
					if ipNet.Contains(dstIP) {
						return ipNet.IP, iface, nil
					}
				}
			}
		}
	}

	return nil, nil, fmt.Errorf("no suitable IP address found for interface: %s", iface.Name)
}

// addrToIPNet converts a route address to an IPNet
func addrToIPNet(addr route.Addr, mask route.Addr) *net.IPNet {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *route.Inet4Addr:
		ip := net.IPv4(a.IP[0], a.IP[1], a.IP[2], a.IP[3])
		if mask != nil {
			switch m := mask.(type) {
			case *route.Inet4Addr:
				mask := net.IPv4Mask(m.IP[0], m.IP[1], m.IP[2], m.IP[3])
				return &net.IPNet{IP: ip, Mask: mask}
			}
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	case *route.Inet6Addr:
		ip := net.IP(a.IP[:])
		if mask != nil {
			switch m := mask.(type) {
			case *route.Inet6Addr:
				mask := net.IPMask(m.IP[:])
				return &net.IPNet{IP: ip, Mask: mask}
			}
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	default:
		return nil
	}
}

// addrToIP converts a route address to an IP
func addrToIP(addr route.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *route.Inet4Addr:
		return net.IPv4(a.IP[0], a.IP[1], a.IP[2], a.IP[3])
	case *route.Inet6Addr:
		return net.IP(a.IP[:])
	default:
		return nil
	}
}

// getSubnetFromIP finds the subnet (IPNet) that contains the given IP
func getSubnetFromIP(iface *net.Interface, ip net.IP) (*net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.Equal(ip) || ipnet.Contains(ip) {
				return ipnet, nil
			}
		}
	}

	return nil, fmt.Errorf("no subnet found for IP %s on interface %s", ip, iface.Name)
}

func getLoopbackInterface() (*net.Interface, error) {
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Loop through interfaces and find "lo0"
	for _, iface := range interfaces {
		if iface.Name == "lo0" {
			return &iface, nil
		}
	}

	// "lo0" not found
	return nil, fmt.Errorf("loopback interface 'lo0' not found")
}
