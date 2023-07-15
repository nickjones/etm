package tracepkts

import (
	"bufio"
	"fmt"
	"strings"
	"log"
)

const (
	ATOM_N = false
	ATOM_E = true
)

type AtomFmtETMv4 struct {
	*GenericTracePacketv4
	format_num int
	taken []bool
}

func DecodeAtomFmt1to3(header byte, loop_count int) AtomFmtETMv4 {
	pkt := AtomFmtETMv4{}

	for i := 0; i < loop_count; i++ {
		if (header>>i)&0x1 == 0 {
			pkt.taken = append(pkt.taken, ATOM_N)
		} else {
			pkt.taken = append(pkt.taken, ATOM_E)
		}
	}
	return pkt
}

func DecodeAtomFmt1(header byte, reader *bufio.Reader) TracePacket {
	pkt := DecodeAtomFmt1to3(header, 1)
	pkt.format_num = 1
	return pkt
}

func DecodeAtomFmt2(header byte, reader *bufio.Reader) TracePacket {
	pkt := DecodeAtomFmt1to3(header, 2)
	pkt.format_num = 2
	return pkt
}

func DecodeAtomFmt3(header byte, reader *bufio.Reader) TracePacket {
	pkt := DecodeAtomFmt1to3(header, 3)
	pkt.format_num = 3
	return pkt
}

func DecodeAtomFmt4(header byte, reader *bufio.Reader) TracePacket {
	pkt := AtomFmtETMv4{format_num: 4}

	pkt_cnt := header&0x3

	switch {
	case pkt_cnt == 0:
		pkt.taken = []bool{ATOM_N, ATOM_E, ATOM_E, ATOM_E}
	case pkt_cnt == 1:
		pkt.taken = []bool{ATOM_N, ATOM_N, ATOM_N, ATOM_N}
	case pkt_cnt == 2:
		pkt.taken = []bool{ATOM_N, ATOM_E, ATOM_N, ATOM_E}
	case pkt_cnt == 3:
		pkt.taken = []bool{ATOM_E, ATOM_N, ATOM_E, ATOM_N}
	}
	return pkt
}

func DecodeAtomFmt5(header byte, reader *bufio.Reader) TracePacket {
	pkt := AtomFmtETMv4{format_num: 5}

	atom_pattern := ((header>>5)&0x1) | (header&0x3)

	switch {
	case atom_pattern == 1:
		pkt.taken = []bool{ATOM_N, ATOM_N, ATOM_N, ATOM_N, ATOM_N}
	case atom_pattern == 2:
		pkt.taken = []bool{ATOM_N, ATOM_E, ATOM_N, ATOM_E, ATOM_N}
	case atom_pattern == 3:
		pkt.taken = []bool{ATOM_E, ATOM_N, ATOM_E, ATOM_N, ATOM_E}
	case atom_pattern == 5:
		pkt.taken = []bool{ATOM_N, ATOM_E, ATOM_E, ATOM_E, ATOM_E}
	default:
		log.Fatalf("Unexpected Atom Format 5 ABC pattern: 0x%02x\n", atom_pattern)
	}
	return pkt
}

func DecodeAtomFmt6(header byte, reader *bufio.Reader) TracePacket {
	pkt := AtomFmtETMv4{format_num: 6}

	a := (header>>5)&0x1
	count := int(header&0x1f)

	for i := 0; i < count + 2; i++ {
		pkt.taken = append(pkt.taken, ATOM_E)
	}
	if a == 1 {
		pkt.taken = append(pkt.taken, ATOM_N)
	} else {
		pkt.taken = append(pkt.taken, ATOM_E)
	}
	return pkt
}

func (pkt AtomFmtETMv4) String() string {
	var sb strings.Builder
	for _, br := range pkt.taken {
		taken := "T"
		if br == false {
			taken = "NT"
		}
		sb.WriteString(fmt.Sprintf("%s ", taken))
	}
	return fmt.Sprintf("Branch(es): %s (Atom Format %d)", sb.String(), pkt.format_num)
}
