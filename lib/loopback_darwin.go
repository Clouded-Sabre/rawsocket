//go:build darwin || freebsd
// +build darwin freebsd

package lib

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// serializeLoopbackPacket handles Darwin/BSD loopback packet serialization
// Darwin/BSD uses a 4-byte loopback header
func serializeLoopbackPacket(buffer gopacket.SerializeBuffer, options gopacket.SerializeOptions, payload []byte) error {
	lo := &layers.Loopback{
		Family: layers.ProtocolFamilyIPv4,
	}
	return gopacket.SerializeLayers(buffer, options,
		lo,
		gopacket.Payload(payload))
}
