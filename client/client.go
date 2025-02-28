//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
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
	Blue   = "\033[34m"
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

// 常量定义（包级别作用域）
const (
	srcPort = 12345        // 源端口
	dstPort = 54321        // 目标端口
	anchor  = "rst_filter" // PF锚点名（此处正确定义）
)

func main() {
	config := parseArgs()
	if config == nil {
		return
	}

	// 检查是否以root权限运行
	if os.Getuid() != 0 {
		fmt.Println("此程序必须以root权限运行，请使用sudo。")
		os.Exit(1)
	}

	// Create the RawSocketCore
	core := rawsocket.NewRawSocketCore(config.ARPCacheTimeout, config.ARPRequestTimeout)

	startClient(core, config)
}

// ================= PF 控制函数 =================
func isPFEnabled() (bool, error) {
	output, err := exec.Command("pfctl", "-s", "info").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("pfctl检查失败: %v\n输出: %s", err, string(output))
	}
	return strings.Contains(string(output), "Status: Enabled"), nil
}

func pfManageAnchor(anchor string, create bool) error {
	action := "anchor"
	if !create {
		action = "no anchor"
	}
	cmd := exec.Command("pfctl", "-a", ".", "-f", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s \"%s\"\n", action, anchor))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("锚点操作失败: %v\n命令输出: %s", err, string(output))
	}
	return nil
}

func pfFlushRules(anchor string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-F", "rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("清理规则失败: %v\n输出: %s", err, string(output))
	}
	return nil
}

func pfLoadRules(anchor, rules string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("加载规则失败: %v\n命令输出: %s", err, string(output))
	}
	return nil
}

// ================= 验证函数 =================
func verifyRuleExactMatch(anchor, expectedRule string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-s", "rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("规则查询失败: %v", err)
	}

	// 严格匹配规则（包括换行符）
	expected := strings.TrimSpace(expectedRule)
	current := strings.TrimSpace(string(output))
	if !strings.Contains(current, expected) {
		return fmt.Errorf("规则不匹配\n当前规则:\n%s\n预期规则:\n%s",
			current, expected)
	}
	return nil
}

func startClient(core *rawsocket.RawSocketCore, config *Config) {
	conn, err := core.DialIP(config.Protocol, config.sourceIP, config.serverIP)
	if err != nil {
		log.Fatalf("Failed to dial to server IP %s: %v", config.serverIP, err)
	}
	defer conn.Close()

	// Extract the dynamic source port from the connection (your DialIP should give you this somehow)
	localAddr := config.sourceIP
	dstAddr := config.serverIP

	if config.Protocol == layers.IPProtocolTCP {
		// 1. 检查PF是否启用
		if enabled, err := isPFEnabled(); err != nil || !enabled {
			fmt.Printf("PF服务未启用: %v\n", err)
			os.Exit(1)
		}

		// 2. 动态管理锚点
		if err := pfManageAnchor(anchor, true); err != nil {
			fmt.Printf("锚点初始化失败: %v\n", err)
			os.Exit(1)
		}
		defer pfManageAnchor(anchor, false) // 确保程序退出时清理

		// 3. 清理旧规则
		if err := pfFlushRules(anchor); err != nil {
			fmt.Printf("清理旧规则失败: %v\n", err)
			os.Exit(1)
		}

		// 4. 构造精准规则（带日志记录）
		rule := fmt.Sprintf(
			"block drop out inet proto tcp "+
				"from %s port = %d to %s port = %d flags R/R\n",
			localAddr.String(), srcPort, dstAddr.String(), dstPort,
		)
		fmt.Println("构造的规则：", rule)

		// 5. 添加规则
		if err := pfLoadRules(anchor, rule); err != nil {
			fmt.Printf("规则添加失败: %v\n", err)
			os.Exit(1)
		}
		defer pfFlushRules(anchor) // 程序退出时清理规则

		// 6. 严格验证规则
		if err := verifyRuleExactMatch(anchor, rule); err != nil {
			fmt.Printf("规则验证失败: %v\n", err)
			os.Exit(1)
		}

		// 7. 保持运行
		fmt.Printf("已成功加载规则：\n%s\n等待 Ctrl+C 退出...\n", strings.TrimSpace(rule))
	}

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

	// Get the raw packet bytes (IP header + TCP layer + payload)
	packetData := buffer.Bytes()

	// Send the packet using the RawIPConn
	_, err = conn.Write(packetData)
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
			log.Println("receiveResponses got stop signal. Exiting...")
			return
		default:
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) // Read wait for 500 ms
			n, srcAddr, err := conn.ReadFrom(buffer)                     // Use ReadFrom instead of Read
			if err != nil {
				// Check if the error is a timeout
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Handle timeout error (no data received within the timeout period)
					continue // Continue waiting for incoming packets or handling close signal
				}
				if err == io.EOF {
					log.Println("Server app got interruption. Stop and exit.")
					return
				}
				fmt.Println("Error reading packet:", err)
				return
			}

			fmt.Println(Red+"We heard some IP packet of total length", n, "from", srcAddr.String(), Reset)

			// Pass the buffer directly to getL4Payload for decoding
			if payload := getL4Payload(buffer[:n], conn.GetProtocol()); payload != nil {
				fmt.Printf(Blue+"Received response: %s\n"+Reset, string(payload))
			} else {
				fmt.Println("No L4 payload found")
			}
		}
	}
}

// getL4Payload extracts the L4 payload from the raw byte slice based on the protocol
func getL4Payload(packetData []byte, protocol layers.IPProtocol) []byte {

	// Check for the correct protocol layer and extract the payload
	switch protocol {
	case layers.IPProtocolTCP:
		// Create a new packet from the raw byte slice
		packet := gopacket.NewPacket(packetData, layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			return tcp.Payload
		}
	case layers.IPProtocolUDP:
		// Create a new packet from the raw byte slice
		packet := gopacket.NewPacket(packetData, layers.LayerTypeUDP, gopacket.Default)
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			return udp.Payload
		}
	case layers.IPProtocolICMPv4:
		// Create a new packet from the raw byte slice
		packet := gopacket.NewPacket(packetData, layers.LayerTypeICMPv4, gopacket.Default)
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			return icmp.Payload
		}
	}

	return nil
}

/* alternative version of receiveResponses using Read function
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

			fmt.Println(Red+"We heard some ip packet of total length", n, Reset)

			// Extract the L4 payload
			if payload := getL4Payload(buffer[:n]); payload != nil {
				fmt.Printf(Red+"Received response: %s\n"+Reset, string(payload))
			} else {
				fmt.Println("No L4 payload found")
			}
		}
	}
}

// use this version when using Read function
// getL4Payload extracts the L4 payload from the packet
func getL4Payload(packetBytes []byte]) []byte {
     // Decode the packet
	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)

	fmt.Println("Packet Layers:")
	for _, layer := range packet.Layers() {
		fmt.Printf("Layer type: %s\n", layer.LayerType())
	}

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		fmt.Println("Found application layer")
		return appLayer.Payload()
	}

	// Handle TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("Found TCP layer with payload: %v\n", tcp.Payload)
		return tcp.Payload
	}

	// Handle UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Printf("Found UDP layer with payload: %v\n", udp.Payload)
		return udp.Payload
	}

	// Handle ICMP layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		fmt.Printf("Found ICMP layer with payload: %v\n", icmp.Payload)
		return icmp.Payload
	}

	fmt.Println("No L4 layer found in packet")
	return nil
}
*/
