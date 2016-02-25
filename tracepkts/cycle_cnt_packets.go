package etmv4_trace_packets

import (
	"bufio"
	"fmt"
	"log"
)

type CycleCountFmt1ETMv4 struct {
	*GenericTracePacketv4
	cycle_count_unknown bool
	cycle_count         uint32
	commit              uint32
}

type CycleCountFmt2ETMv4 struct {
	*GenericTracePacketv4
	*CycleCountFmt1ETMv4
}

type CycleCountFmt3ETMv4 struct {
	*GenericTracePacketv4
	*CycleCountFmt1ETMv4
}

func DecodeCycleCountFmt1(header byte, reader *bufio.Reader) TracePacket {
	pkt := CycleCountFmt1ETMv4{}

	if header&0x1 == 1 {
		pkt.cycle_count_unknown = true
	}

	for i := 0; ; i++ {
		commit_byte, err := reader.ReadByte()

		if err != nil {
			log.Printf("Error reading bytes for Cycle Count on COMMIT bytes.")
			return nil
		}

		pkt.commit |= uint32(commit_byte&0x7f) << uint(7*i)

		if commit_byte&0x80 == 0 {
			break
		}
	}

	var count_byte byte
	var err error
	i := 0

	// Bail early if it's unknown
	if pkt.cycle_count_unknown {
		return pkt
	}

	for ; i < 2; i++ {
		count_byte, err = reader.ReadByte()

		if err != nil {
			log.Printf("Error reading bytes for Cycle Count on COUNT bytes.")
			return nil
		}

		pkt.cycle_count |= uint32(count_byte&0x7f) << uint(7*i)

		if count_byte&0x80 == 0x0 {
			break
		}
	}

	// Copy last COUNT[19:14] byte
	if i == 2 && count_byte&0x80 == 0x80 {
		count_byte, err = reader.ReadByte()

		if err != nil {
			log.Printf("Error reading bytes for Cycle Count on last COUNT byte.")
			return nil
		}

		pkt.cycle_count |= uint32(count_byte&0x3f) << 14
	}

	return pkt
}

func DecodeCycleCountFmt2(header byte, reader *bufio.Reader) TracePacket {
	pkt := CycleCountFmt2ETMv4{}

	f := header & 0x1

	payload, err := reader.ReadByte()

	if err != nil {
		log.Printf("Error parsing payload byte for Cycle Count.")
		return nil
	}

	pkt.cycle_count = uint32(payload & 0x0f)
	// AAAA field is either AAAA+1 (F=0) or max_spec_depth+AAAA-15 (F=1)
	if f == 0 {
		pkt.commit = uint32(payload&0xf0>>4) + 1
	}

	return pkt
}

func DecodeCycleCountFmt3(header byte, reader *bufio.Reader) TracePacket {
	pkt := CycleCountFmt3ETMv4{}

	pkt.commit = uint32(header & 0x3)
	pkt.cycle_count = uint32(header&0x0c) >> 2

	return pkt
}

func (pkt CycleCountFmt1ETMv4) String() string {
	if pkt.cycle_count_unknown {
		return fmt.Sprintf("Cycle Count Format 1: Commit: %0d Cycle Count Unknown", pkt.commit)
	} else {
		return fmt.Sprintf("Cycle Count Format 1: Commit: %0d Cycle Count: %0d", pkt.commit, pkt.cycle_count)
	}
}
