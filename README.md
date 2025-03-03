# Rawsocket

**Rawsocket** is a Golang raw socket implementation for Windows and macOS that mimics the behavior of Linux’s `net.IPConn`. Due to critical limitations of the official raw socket implementation on Windows and macOS, the standard `net.IPConn` does not work reliably on those platforms. Rawsocket leverages [gopacket](https://github.com/google/gopacket) to implement functions such as:

- `DialIP`
- `ListenIP`
- `Read`
- `ReadFrom`
- `Write`
- `WriteTo`
- `SetReadDeadline`
- `Close`

This unified interface lets you write cross-platform code that handles raw IP packets similarly to how you would on Linux.

---

## Overview

Rawsocket provides a consistent raw IP packet interface across Windows, macOS, and Linux. It abstracts away OS-specific limitations so you can focus on your application logic. On Windows and macOS, rawsocket uses gopacket and requires additional libraries for packet capture and injection.

---

## Requirements

### Windows
- **Npcap**: Install [Npcap](https://nmap.org/npcap/) (ensure it is in "WinPcap API-compatible Mode").
- **WinDivert**: When compiling the sample client (`client.go`), download `windivert64.sys` and `windivert.dll` and place them in the same directory as the executable. Please note that Rawsocket lib itself does not depend on WinDivert, but in real implementation, you may need it to make your own client application work if you don't want to see a lot of RST packets sending out from client machine.
- **Administrator Privileges**: Must run as Administrator.

### macOS
- **libpcap**: Install via Homebrew (`brew install libpcap`) or through other means.
- **Administrator Privileges**: Elevated privileges may be required.

### Linux
- Native raw socket support is available via go standard net lib. Rawsocket just try to extend it to offers a consistent interface on Windows and macos platforms.

---

## Installation

To install Rawsocket, run:

```bash
go get github.com/Clouded-Sabre/rawsocket
```

Make sure you have [gopacket](https://github.com/google/gopacket) installed as well.

---

## Sample Code

The repository includes two sample programs:
- **client.go**: Sample client using rawsocket.
- **server_win.go**: Sample server for Windows using rawsocket.

### Running the Server on Windows

1. **Install Npcap** on your system.
2. Build the server:
   ```bash
   go build -o server_win.exe server_win.go
   ```
3. Run `server.exe` in a Command Prompt with Administrator privileges.

**Note:**  
For TCP, the sample server creates a dummy TCP socket that binds to port `54321` (without accepting connections) so that the kernel knows the port is in use and does not send RST packets when raw TCP packets are exchanged.

### Running the Client on Windows

1. **Install Npcap** on your system.
2. Download **WinDivert** files (`windivert64.sys` and `windivert.dll`) and place them in the same directory as the client executable.
3. Build the client:
   ```bash
   go build -o client.exe client.go
   ```
4. Run `client.exe` as Administrator.

### Running on macOS

Build and run the code normally using `go build` (ensuring **libpcap** is installed). Elevated privileges may be necessary.

---

## Usage

Rawsocket is used in a similar way to Linux’s `net.IPConn`. For example, on Linux you might write:

```go
listener, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP("192.168.1.100")})
```

With Rawsocket on Windows or macOS:

```go
core := rawsocket.NewRawSocketCore(arpCacheTimeout, arpRequestTimeout, true)
listener, err := core.ListenIP(net.ParseIP("192.168.1.100"), layers.IPProtocolTCP)
```

The interface supports functions such as `DialIP`, `Read`, `ReadFrom`, `Write`, `WriteTo`, and `SetReadDeadline` for cross-platform raw packet transmission.

---

## Workarounds & Known Issues

### TCP RST packets blocking
When running rawsocket client or server app on Windows and macOS, the system’s TCP stack may send RST packets when it receives raw TCP packets on an unbound port.  
**Workaround:**
- for server app, create a dummy tcp server using stardard net.lib which listens at the port but do not accept any connection. This tells the kernel that the port is in use, preventing RST packets.
- for client app, use Windvert (windows) or pf filtering rules(macos) to block outgoing RST packet.
Please see sample code for details.


## Building and Running

Ensure you run with proper privileges:
- **Windows:** Run executables as Administrator.
- **macOS:** Use elevated privileges if necessary.

For building client in Windows, ensure the following files are present in the executable’s directory:
- `windivert64.sys`
- `windivert.dll`

---

## Contributing

Contributions, bug reports, and feature requests are welcome! Please submit pull requests or open issues on GitHub.

---

## License

This project is licensed under the MIT License.
