package etmv4_trace_packets

import (
	"bufio"
	"fmt"
	"log"
)

type ExceptionETMv4 struct {
	*GenericTracePacketv4
	e1e0        uint8
	etype       uint16
	p           bool
	return_addr TracePacket
}

type ExceptionReturnETMv4 struct {
	*GenericTracePacketv4
}

const (
	PE_RESET = iota
	DEBUG_HALT
	CALL
	TRAP
	SYSTEM_ERROR
	RES5
	INST_DEBUG
	DATA_DEBUG
	RES8
	RES9
	ALIGNMENT
	INST_FAULT
	DATA_FAULT
	RES13
	IRQ
	FIQ
	IMP_DEF0
	IMP_DEF1
	IMP_DEF2
	IMP_DEF3
	IMP_DEF4
	IMP_DEF5
	IMP_DEF6
	RES18
	RES19
	RES20
	RES21
	RES22
	RES23
	RES24
	RES25
	RES26
	RES27
	RES28
	RES29
	RES30
	RES31
)

var etypes = [...]string{
	"PE reset",
	"Debug halt",
	"Call",
	"Trap",
	"System error",
	"Reserved",
	"Inst debug",
	"Data debug",
	"Reserved",
	"Reserved",
	"Alignment",
	"Inst fault",
	"Data fault",
	"Reserved",
	"IRQ",
	"FIQ",
	"Implementation Defined 0",
	"Implementation Defined 1",
	"Implementation Defined 2",
	"Implementation Defined 3",
	"Implementation Defined 4",
	"Implementation Defined 5",
	"Implementation Defined 6",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
}

func DecodeException(header byte, reader *bufio.Reader) TracePacket {
	pkt := ExceptionETMv4{}

	eheader_info0, err := reader.ReadByte()
	if err != nil {
		log.Println("Error reading stream decoding Exception.")
		return nil
	}
	pkt.e1e0 = uint8(eheader_info0&0x6>>5 | eheader_info0&0x1)

	pkt.etype = uint16(eheader_info0 & 0x3e >> 1)

	if eheader_info0&0x80 == 0x80 {
		eheader_info1, err := reader.ReadByte()
		if err != nil {
			log.Println("Error reading stream decoding Exception.")
			return nil
		}
		pkt.etype |= uint16(eheader_info1 & 0x1f)
		if eheader_info1&0x20 == 0x20 {
			pkt.p = true
		}
	}
	addr_header, err := reader.ReadByte()

	switch addr_header {
	case 0x9a, 0x9b:
		pkt.return_addr = DecodeLong32b(addr_header, reader)
	case 0x9d, 0x9e:
		pkt.return_addr = DecodeLong64b(addr_header, reader)
	default:
		pkt.return_addr = nil
		log.Println("Error decoding header for preferred return address after exception.")
	}

	return pkt
}

func DecodeExceptionReturn(header byte, reader *bufio.Reader) TracePacket {
	return ExceptionReturnETMv4{}
}

func (pkt ExceptionETMv4) String() string {
	return fmt.Sprintf("Exception: [E1:E0]: %x Type: %s Preferred Return Address: %s", pkt.e1e0, etypes[pkt.etype], pkt.return_addr.String())
}

func (ExceptionReturnETMv4) String() string {
	return "Exception Return"
}
