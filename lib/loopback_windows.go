//go:build windows
// +build windows

package lib

import "github.com/google/gopacket"

// serializeLoopbackPacket handles Windows loopback packet serialization
// Windows doesn't use any special header for loopback interfaces
func serializeLoopbackPacket(buffer gopacket.SerializeBuffer, options gopacket.SerializeOptions, payload []byte) error {
	return gopacket.SerializeLayers(buffer, options,
		gopacket.Payload(payload))
}
