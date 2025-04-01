package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	// Define command-line flags
	serverAddr := flag.String("server", "localhost", "Server address")
	serverPort := flag.String("port", "8080", "Server port")

	// Parse command-line arguments
	flag.Parse()

	// Construct the server address
	address := net.JoinHostPort(*serverAddr, *serverPort)

	// Connect to the server
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting:", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send the message
	message := "hello!\n"
	fmt.Fprint(conn, message)

	// Read the response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		if err.Error() == "EOF" {
			fmt.Println("Server closed the connection.")
			return
		}
		fmt.Println("Error reading response:", err)
		return
	}
	fmt.Println("Response from server:", response)
}
