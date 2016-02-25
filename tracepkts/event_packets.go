package tracepkts

import (
	"bufio"
	"bytes"
	"fmt"
)

const (
	EVENT_WIDTH = 4
)

type EventETMv4 struct {
	*GenericTracePacketv4
	event [EVENT_WIDTH]bool
}

func DecodeEvent(header byte, reader *bufio.Reader) TracePacket {
	pkt := EventETMv4{}

	for i := 0; i < EVENT_WIDTH; i++ {
		if (header>>uint(i))&0x1 == 1 {
			pkt.event[i] = true
		}
	}
	return pkt
}

func (pkt EventETMv4) String() string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("Event[0]=%t", pkt.event[0]))

	for i := 1; i < EVENT_WIDTH; i++ {
		buffer.WriteString(fmt.Sprintf(" Event[%0d]=%t", i, pkt.event[i]))
	}
	return buffer.String()
}
