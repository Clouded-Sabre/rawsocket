//go:build windows
// +build windows

package lib

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// WindowsLoopbackHeader represents the 4-byte header used in Windows loopback packets
type WindowsLoopbackHeader struct {
	layers.BaseLayer
	Family uint16 // Address family (2 for IPv4)
}

func (h *WindowsLoopbackHeader) LayerType() gopacket.LayerType {
	return layers.LayerTypeLoopback
}

func (h *WindowsLoopbackHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}

	// Write address family in little-endian (Windows standard)
	binary.LittleEndian.PutUint16(bytes[0:2], h.Family)
	// Last 2 bytes are unused/reserved
	binary.LittleEndian.PutUint16(bytes[2:4], 0)

	return nil
}

// serializeLoopbackPacket handles Windows loopback packet serialization
func serializeLoopbackPacket(buffer gopacket.SerializeBuffer, options gopacket.SerializeOptions, payload []byte) error {
	header := &WindowsLoopbackHeader{
		Family: 2, // AF_INET for IPv4
	}

	return gopacket.SerializeLayers(buffer, options,
		header,
		gopacket.Payload(payload))
}
