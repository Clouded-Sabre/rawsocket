//go:build windows
// +build windows

package lib

import (
	"fmt"
	"net"
	"os"

	"github.com/moriyoshi/routewrapper"
)

// getLocalIP finds the local IP that can route to the given destination IP
func GetLocalIP(dstIP net.IP) (net.IP, *net.Interface, net.IP, error) {
	w, err := routewrapper.NewRouteWrapper()
	if err != nil {
		fmt.Printf("Error initializing route wrapper: %v\n", err)
		os.Exit(1)
	}

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

	routes, err := w.Routes()
	if err != nil {
		return nil, nil, nil, err
	}

	var bestRoute *routewrapper.Route
	bestMatchLength := 0
	var defaultRoute *routewrapper.Route

	for i, route := range routes {
		if route.Destination.String() == "0.0.0.0/0" {
			// Track the first default route found
			if defaultRoute == nil {
				defaultRoute = &route
			}
			continue
		}

		if route.Destination.Contains(dstIP) {
			ifName := "*"
			if route.Interface != nil {
				ifName = route.Interface.Name
			}
			if Debug {
				fmt.Printf("%d: %s %s\n", i, route.Destination.String(), ifName)
			}
			_, routeNet, _ := net.ParseCIDR(route.Destination.String())
			dstMaskSize, _ := routeNet.Mask.Size()
			if dstMaskSize > bestMatchLength {
				bestMatchLength = dstMaskSize
				bestRoute = &route
			}
		}
	}

	var (
		chosenIP, gatewayIP net.IP
		chosenInterface     *net.Interface
	)

	if bestRoute != nil && bestRoute.Interface != nil {
		chosenInterface = bestRoute.Interface
		if bestRoute.Gateway != nil {
			chosenIP, err = getInterfaceIP(bestRoute.Interface, bestRoute.Gateway)
		} else {
			chosenIP, err = getInterfaceIP(bestRoute.Interface, dstIP)
		}
	} else if defaultRoute != nil && defaultRoute.Interface != nil {
		chosenInterface = defaultRoute.Interface
		if defaultRoute.Gateway != nil {
			chosenIP, err = getInterfaceIP(defaultRoute.Interface, defaultRoute.Gateway)
			gatewayIP = defaultRoute.Gateway // Set the gateway IP
		} else {
			chosenIP, err = getInterfaceIP(defaultRoute.Interface, dstIP)
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

	return chosenIP, chosenInterface, gatewayIP, nil
}

// getInterfaceIP retrieves the local IP address associated with the given network interface
func getInterfaceIP(iface *net.Interface, gatewayIP net.IP) (net.IP, error) {
	//fmt.Println("iface:", iface, "     GatewayIP:", gatewayIP)
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		//if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil && ipNet.Contains(gatewayIP) {
				return ipNet.IP, nil
			}
		}
	}

	return nil, fmt.Errorf("no suitable IP address found for interface: %s", iface.Name)
}

func getLoopbackInterface() (*net.Interface, error) {
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Loop through interfaces to find the loopback interface
	for _, iface := range interfaces {
		if (iface.Flags&net.FlagLoopback) != 0 || iface.HardwareAddr == nil || len(iface.HardwareAddr) == 0 {
			return &iface, nil
		}
	}

	// Loopback interface not found
	return nil, fmt.Errorf("loopback interface not found")
}
