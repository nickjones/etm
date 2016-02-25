package tracepkts

import (
	"bufio"
	"fmt"
)

const (
	ATOM_N = 0
	ATOM_E = 1
)

type AtomFmt1ETMv4 struct {
	*GenericTracePacketv4
	taken bool
}

func DecodeAtomFmt1(header byte, reader *bufio.Reader) TracePacket {
	pkt := AtomFmt1ETMv4{}

	if header&0x1 == ATOM_N {
		pkt.taken = false
	} else {
		pkt.taken = true
	}

	return pkt
}

func (pkt AtomFmt1ETMv4) String() string {
	taken := "Taken"
	if pkt.taken == false {
		taken = "Not Taken"
	}
	return fmt.Sprintf("Atom Format 1 Branch %s", taken)
}
