package etmv4_trace_packets

import (
	"bufio"
	"log"
)

type AsyncETMv4 struct {
	*GenericTracePacketv4
}

type OverflowETMv4 struct {
	*GenericTracePacketv4
}

func DecodeAsync(header byte, reader *bufio.Reader) TracePacket {
	async_byte_count := 0

	for async_byte_count < 10 {
		next_byte, err := reader.ReadByte()
		if err != nil {
			log.Println("Error reading file looking for another async byte.")
		}
		if next_byte == 0x00 {
			async_byte_count++
		} else {
			log.Printf("Unexpected byte in async pkt decode: %x", next_byte)
		}
	}
	last_byte, err := reader.ReadByte()

	if err != nil || last_byte != 0x80 {
		log.Printf("Failed to detect ASYNC Packet")
		return nil
	}
	return AsyncETMv4{}
}

func DecodeOverflow(header byte, reader *bufio.Reader) TracePacket {
	// Payload byte is meaningless
	_, err := reader.ReadByte()

	if err != nil {
		log.Printf("Error trying to read payload byte of Overflow")
		return nil
	}
	return OverflowETMv4{}
}

func (AsyncETMv4) String() string {
	return "Async"
}

func (OverflowETMv4) String() string {
	return "Overflow"
}
