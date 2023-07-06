package tracepkts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
)

type Long64bAddrETMv4 struct {
	*GenericTracePacketv4
	is      uint8
	address uint64
	width   uint8
}

type CompressedAddrETMv4 struct {
	*GenericTracePacketv4
	is     uint8
	offset uint64
	width  uint8
}

const (
	ADDR_COMP_STK_DEPTH = 3
)

type ExactAddrETMv4 struct {
	*GenericTracePacketv4
	exact_match [ADDR_COMP_STK_DEPTH]bool
}

const (
	EL0 = 0
	EL1 = 1
	EL2 = 2
	EL3 = 3
)

type ContextETMv4 struct {
	*GenericTracePacketv4
	payload_valid bool
	el            int
	a64           bool
	ns            bool
	vmid_valid    bool
	vmid          uint32
	cid_valid     bool
	cid           uint32
}

func DecodeExactAddr(header byte, reader *bufio.Reader) TracePacket {
	pkt := ExactAddrETMv4{}

	for i := 0; i < ADDR_COMP_STK_DEPTH; i++ {
		if (header>>uint(i))&0x1 == 0x1 {
			pkt.exact_match[i] = true
		}
	}
	return pkt
}

func DecodeShortAddr(header byte, reader *bufio.Reader) TracePacket {
	pkt := CompressedAddrETMv4{width: 8}

	if header == 0x95 {
		pkt.is = 0
	} else {
		pkt.is = 1
	}

	addr_byte, err := reader.ReadByte()
	if err != nil {
		log.Println("Error reading byte for Short Address packet decode.")
		return nil
	}
	addr_int := uint64(addr_byte)
	pkt.offset = (addr_int & 0x7f) << uint(2-pkt.is)

	if addr_byte&0x80 == 0x80 {
		addr_byte, err = reader.ReadByte()
		if err != nil {
			log.Println("Error reading byte for Short Address packet decode.")
			return nil
		}
		addr_int = uint64(addr_byte)

		if pkt.is == 0 {
			addr_int &= 0x7f
		}
		pkt.offset |= addr_int << uint(9-pkt.is)
		pkt.width = 16
	}

	return pkt
}

func DecodeLong32b(header byte, reader *bufio.Reader) TracePacket {
	pkt := CompressedAddrETMv4{width: 32}

	if header == 0x9a {
		pkt.is = 0
	} else {
		pkt.is = 1
	}

	// First two bytes are special
	addr_byte, err := reader.ReadByte()
	if err != nil {
		log.Println("Error reading byte for Long Address 32b packet decode.")
		return nil
	}
	addr_int := uint64(addr_byte)
	pkt.offset = (addr_int & 0x7f) << uint(2-pkt.is)

	addr_byte, err = reader.ReadByte()
	if err != nil {
		log.Println("Error reading byte for Long Address 32b packet decode.")
		return nil
	}
	addr_int = uint64(addr_byte)

	if pkt.is == 0 {
		addr_int &= 0x7f
	}
	pkt.offset |= addr_int << uint(9-pkt.is)

	for i := 2; i < 4; i++ {
		addr_byte, err := reader.ReadByte()
		if err != nil {
			log.Println("Error reading byte for Long Address 32b packet decode.")
			return nil
		}
		addr_int := uint64(addr_byte)
		pkt.offset |= addr_int << uint(8*i)
	}

	return pkt
}

func DecodeLong64b(header byte, reader *bufio.Reader) TracePacket {
	pkt := Long64bAddrETMv4{width: 64}

	if header == 0x9d {
		pkt.is = 0
	} else {
		pkt.is = 1
	}

	// First two bytes are special
	addr_byte, err := reader.ReadByte()
	if err != nil {
		log.Println("Error reading byte for Long Address 64b packet decode.")
		return nil
	}
	addr_int := uint64(addr_byte)
	pkt.address = (addr_int & 0x7f) << uint(2-pkt.is)

	addr_byte, err = reader.ReadByte()
	if err != nil {
		log.Println("Error reading byte for Long Address 64b packet decode.")
		return nil
	}
	addr_int = uint64(addr_byte)

	if pkt.is == 0 {
		addr_int &= 0x7f
	}
	pkt.address |= addr_int << uint(9-pkt.is)

	for i := 2; i < 8; i++ {
		addr_byte, err := reader.ReadByte()
		if err != nil {
			log.Println("Error reading byte for Long Address 64b packet decode.")
			return nil
		}
		addr_int := uint64(addr_byte)
		pkt.address |= addr_int << uint(8*i)
	}

	return pkt
}

func DecodeContext(header byte, reader *bufio.Reader) TracePacket {
	pkt := ContextETMv4{}

	if header&0x1 == 0 {
		pkt.payload_valid = false
		return pkt
	} else {
		pkt.payload_valid = true
	}

	info_byte, err := reader.ReadByte()
	if err != nil {
		log.Println("Error reading byte for Context.")
		return nil
	}

	// Exception Level
	pkt.el = int(info_byte & 0x3)

	// SF bit (AArch64/AArch32)
	if info_byte&0x10 == 0x10 {
		pkt.a64 = true
	} else {
		pkt.a64 = false
	}

	// Non-secure status
	if info_byte&0x20 == 0x20 {
		pkt.ns = true
	} else {
		pkt.ns = false
	}

	// VMID
	if info_byte&0x40 == 0x40 {
		pkt.vmid_valid = true
		vmid := make([]byte, 4) // Expanded to 4B on v4.1
		count, err := reader.Read(vmid)

		if err != nil || count != 1 {
			log.Println("Error reading VMID byte for Context.")
		}

		for k, v := range vmid {
			pkt.vmid |= uint32(v) << uint(8*k)
		}
	} else {
		pkt.vmid_valid = false
	}

	// CONTEXTID
	if info_byte&0x80 == 0x80 {
		pkt.cid_valid = true
		cid := make([]byte, 4)
		count, err := reader.Read(cid)

		if err != nil || count != 4 {
			log.Println("Error reading CONTEXTID bytes for Context.")
		}

		for k, v := range cid {
			pkt.cid |= uint32(v) << uint(8*k)
		}
	}

	return pkt
}

func (pkt Long64bAddrETMv4) Address() uint64 {
	return pkt.address
}

func (pkt Long64bAddrETMv4) IS() uint8 {
	return pkt.is
}

func (pkt Long64bAddrETMv4) String() string {
	return fmt.Sprintf("IS%d Address = 0x%016x (%d-bit)", pkt.is, pkt.address, pkt.width)
}

func (pkt CompressedAddrETMv4) String() string {
	return fmt.Sprintf("IS%d Offset = 0x%x (%d-bit)", pkt.is, pkt.offset, pkt.width)
}

func (pkt CompressedAddrETMv4) StringWithBase(base uint64) string {
	addr := pkt.AddrWithBase(base)
	return fmt.Sprintf("IS%d Address = %016x", pkt.is, addr)
}

func (pkt CompressedAddrETMv4) AddrWithBase(base uint64) uint64 {
	return ((base >> uint64(pkt.width)) << uint64(pkt.width)) | pkt.offset
}

func (pkt CompressedAddrETMv4) IS() uint8 {
	return pkt.is
}

func (pkt CompressedAddrETMv4) Width() uint8 {
	return pkt.width
}

func (pkt ExactAddrETMv4) String() string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("address_reg[0] match=%t", pkt.exact_match[0]))

	for i := 1; i < ADDR_COMP_STK_DEPTH; i++ {
		if pkt.exact_match[i] {
			buffer.WriteString(fmt.Sprintf("address_reg[%0d] match=%t", i, pkt.exact_match[i]))
		}
	}

	return buffer.String()
}

func (pkt ExactAddrETMv4) Entry() (uint8, error) {
	for i := uint8(0); i < ADDR_COMP_STK_DEPTH; i++ {
		if pkt.exact_match[i] {
			return i, nil
		}
	}
	return 3, errors.New("Exact match packet but all bits were false?")
}

func (pkt ContextETMv4) String() string {
	if pkt.payload_valid == false {
		return "Context (no payload)"
	}

	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("Context: EL: %d A64: %t NS: %t", pkt.el, pkt.a64, pkt.ns))

	if pkt.vmid_valid {
		buffer.WriteString(fmt.Sprintf(" VMID: %x", pkt.vmid))
	}

	if pkt.cid_valid {
		buffer.WriteString(fmt.Sprintf(" CID: %x", pkt.cid))
	}

	return buffer.String()
}
