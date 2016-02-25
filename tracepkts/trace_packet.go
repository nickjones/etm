package tracepkts

import (
	"bufio"
	"log"
)

type GenericTracePacketv4 struct {
	// header byte
}

type TracePacket interface {
	String() string
}

func DecodePacket(header byte, reader *bufio.Reader) TracePacket {
	var pkt TracePacket
	switch {
	case header == 0x00:
		next_byte, err := reader.Peek(1)
		if err != nil {
			log.Println("Malformed extended packet, next byte doesn't exist!")
			return nil
		}
		switch next_byte[0] {
		case 0x00:
			// Continue reading Async
			pkt = DecodeAsync(header, reader)
		case 0x05:
			// Overflow
			pkt = DecodeOverflow(header, reader)
		}
	case header == 0x01:
		pkt = DecodeTraceInfo(header, reader)
	case header >= 0x02 && header <= 0x03:
		pkt = DecodeTimestamp(header, reader)
	case header == 0x04:
		pkt = DecodeTraceOn(header, reader)
	case header == 0x06:
		pkt = DecodeException(header, reader)
	case header == 0x07:
		pkt = DecodeExceptionReturn(header, reader)
	case header >= 0x0c && header <= 0x0d:
		pkt = DecodeCycleCountFmt2(header, reader)
	case header >= 0x0e && header <= 0x0f:
		pkt = DecodeCycleCountFmt1(header, reader)
	case header >= 0x10 && header <= 0x1f:
		pkt = DecodeCycleCountFmt3(header, reader)
	case header == 0x2d:
		pkt = DecodeCommit(header, reader)
	case header >= 0x71 && header <= 0x7f:
		pkt = DecodeEvent(header, reader)
	case header >= 0x80 && header <= 0x81:
		pkt = DecodeContext(header, reader)
	case header >= 0x90 && header <= 0x93:
		pkt = DecodeExactAddr(header, reader)
	case header >= 0x95 && header <= 0x96:
		pkt = DecodeShortAddr(header, reader)
	case header >= 0x9a && header <= 0x9b:
		pkt = DecodeLong32b(header, reader)
	case header >= 0x9d && header <= 0x9e:
		pkt = DecodeLong64b(header, reader)
	case header >= 0xf6 && header <= 0xf7:
		pkt = DecodeAtomFmt1(header, reader)
	}
	return pkt
}
