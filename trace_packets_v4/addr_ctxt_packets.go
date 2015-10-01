package etmv4_trace_packets

import (
	"bufio"
	"bytes"
	"fmt"
	// "io"
	"log"
)

type Long64bAddrETMv4 struct {
	*GenericTracePacketv4
	is      int8
	address uint64
}

type CompressedAddrETMv4 struct {
	*GenericTracePacketv4
	is     int8
	offset uint32
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

func DecodeLong64bIS0(header byte, reader *bufio.Reader) TracePacket {
	pkt := Long64bAddrETMv4{}

	// First two bytes are special
	addr_byte, err := reader.ReadByte()
	if err != nil {
		log.Println("Error reading byte for Long Address 64b packet decode.")
		return nil
	}
	addr_int := uint64(addr_byte)
	pkt.address = (addr_int & 0x7f) << 2

	addr_byte, err = reader.ReadByte()
	if err != nil {
		log.Println("Error reading byte for Long Address 64b packet decode.")
		return nil
	}
	addr_int = uint64(addr_byte)
	pkt.address |= (addr_int & 0x7f) << 9

	// This seems to miss bytes for some reason!?
	// rest := make([]byte, 6)
	// count, err := io.ReadFull(reader, rest)
	// log.Printf("Read %d bytes", count)

	// if err != nil || count != 6 {
	// 	log.Println("Error reading byte for Long Address 64b packet decode.")
	// 	return nil
	// }

	// fmt.Printf("%#v\n", rest)

	// for k, v := range rest {
	// 	log.Printf("v:%x 16+8*k:%d", v, 16+8*k)
	// 	pkt.address |= uint64(v) << uint64(16+8*k)
	// }

	for i := 2; i < 8; i++ {
		addr_byte, err := reader.ReadByte()
		if err != nil {
			log.Println("Error reading byte for Long Address 64b packet decode.")
			return nil
		}
		addr_int := uint64(addr_byte)
		pkt.address |= addr_int << uint(8*i)
	}

	pkt.is = 0
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
		vmid := make([]byte, 1) // Expanded to 4B on v4.1
		_, err = reader.Read(vmid)

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
		_, err = reader.Read(cid)

		for k, v := range cid {
			pkt.cid |= uint32(v) << uint(8*k)
		}
	}

	return pkt
}

func (pkt Long64bAddrETMv4) String() string {
	return fmt.Sprintf("IS%d Address = %x", pkt.is, pkt.address)
}

func (pkt CompressedAddrETMv4) String() string {
	return "I don't know how to print this yet"
}

func (pkt ContextETMv4) String() string {
	if pkt.payload_valid == false {
		return "Context (no payload)"
	}

	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("Context: EL: %d A64: %t NS: %t", pkt.el, pkt.a64, pkt.ns))

	if pkt.vmid_valid {
		buffer.WriteString(fmt.Sprintf(" VMID: %0h", pkt.vmid))
	}

	if pkt.cid_valid {
		buffer.WriteString(fmt.Sprintf(" CID: %0h", pkt.cid))
	}

	return buffer.String()
}
