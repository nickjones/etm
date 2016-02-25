package tracepkts

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
)

type TraceInfoETMv4 struct {
	*GenericTracePacketv4
	plctl           uint8
	cc_enabled      bool
	cond_enabled    uint8
	p0_load         bool
	p0_store        bool
	curr_spec_depth uint32
	cc_threshold    uint32
	p0_key_max      uint8
}

type TraceOnETMv4 struct {
	*GenericTracePacketv4
}

type TimestampETMv4 struct {
	*GenericTracePacketv4
	timestamp         uint64
	cycle_count_valid bool
	cycle_count       uint32
}

func DecodeTraceInfo(header byte, reader *bufio.Reader) TracePacket {
	pkt := TraceInfoETMv4{}

	// ETMv4 only specifies one byte for PLCTL
	plctl, err := reader.ReadByte()

	if err != nil {
		log.Println("Error reading byte for Trace Info packet decode.")
		return nil
	}

	pkt.plctl = uint8(plctl)

	// INFO section
	if plctl&0x1 == 1 {
		info, err := reader.ReadByte()

		if err != nil {
			log.Println("Error reading Trace Info byte for INFO block.")
			return nil
		}

		if info&0x1 == 1 {
			pkt.cc_enabled = true
		} else {
			pkt.cc_enabled = false
		}

		pkt.cond_enabled = uint8(info & 0xe >> 1)

		if info&0x10 == 0x10 {
			pkt.p0_load = true
		} else {
			pkt.p0_load = false
		}

		if info&0x20 == 0x20 {
			pkt.p0_store = true
		} else {
			pkt.p0_store = false
		}
	}
	// KEY section
	if plctl&0x2 == 0x2 {
		key, err := reader.ReadByte()

		if err != nil {
			log.Println("Error reading Trace Info byte for KEY block.")
			return nil
		}

		pkt.p0_key_max = uint8(key)
	}
	// SPEC section
	if plctl&0x4 == 0x4 {
		spec, err := reader.ReadByte()

		if err != nil {
			log.Println("Error reading Trace Info byte for SPEC block.")
			return nil
		}

		pkt.curr_spec_depth = uint32(spec & 0x7f)

		for i := 0; ; i++ {
			if spec&0x80 == 0x80 {
				spec, err = reader.ReadByte()
				if err != nil {
					log.Println("Error reading Trace Info byte for SPEC block.")
					return nil
				}

				pkt.curr_spec_depth |= uint32(spec & 0x7f << uint(7*i))
			} else {
				break
			}
		}
	}
	// CYCT section
	if plctl&0x8 == 0x8 {
		cyct0, err := reader.ReadByte()

		if err != nil {
			log.Println("Error reading Trace Info byte for CYCT block.")
			return nil
		}

		pkt.cc_threshold = uint32(cyct0 & 0x7f)

		if cyct0&0x80 == 0x80 {
			cyct1, err := reader.ReadByte()

			if err != nil {
				log.Println("Error reading Trace Info byte for CYCT block.")
				return nil
			}

			pkt.cc_threshold |= uint32(cyct1 & 0x1f << 7)
		}
	}
	return pkt
}

func DecodeTraceOn(header byte, reader *bufio.Reader) TracePacket {
	pkt := TraceOnETMv4{}
	return pkt
}

func DecodeTimestamp(header byte, reader *bufio.Reader) TracePacket {
	pkt := TimestampETMv4{}

	if header&0x1 == 1 {
		pkt.cycle_count_valid = true
	}

	ts_pos := 0
	for ; ts_pos < 8; ts_pos++ {
		ts_byte, err := reader.ReadByte()

		if err != nil {
			log.Println("Error reading Timestamp byte.")
			return nil
		}

		pkt.timestamp |= uint64(ts_byte&0x7f) << uint(ts_pos*7)
		if ts_byte&0x80 == 0 {
			break
		}
	}
	// Full TS packet, copy last byte
	if ts_pos == 8 {
		ts_byte, err := reader.ReadByte()

		if err != nil {
			log.Println("Error reading Timestamp byte.")
			return nil
		}

		pkt.timestamp |= uint64(ts_byte << 56)
	}

	if pkt.cycle_count_valid {
		count_pos := 0
		var count_byte byte
		var err error

		for ; count_pos < 2; count_pos++ {
			count_byte, err = reader.ReadByte()

			if err != nil {
				log.Println("Error reading Timestamp byte.")
				return nil
			}

			pkt.cycle_count |= uint32(count_byte & 0x7f << uint(count_pos*7))

			if count_byte&0x80 == 0 {
				break
			}
		}

		// Copy last [19:14]
		if count_pos == 2 && count_byte&0x80 == 0x80 {
			count_byte, err = reader.ReadByte()

			if err != nil {
				log.Println("Error reading Timestamp byte.")
				return nil
			}

			pkt.cycle_count |= uint32(count_byte & 0x3f << 14)
		}
	}
	return pkt
}

func (pkt TraceInfoETMv4) String() string {
	return fmt.Sprintf("Trace Info: PLCTL: 0x%x cc_enabled: %t cond_enabled: 0x%x p0_load: %t p0_store: %t curr_spec_depth: 0x%x cc_threshold: 0x%x p0_key_max: 0x%x", pkt.plctl, pkt.cc_enabled, pkt.cond_enabled, pkt.p0_load, pkt.p0_store, pkt.curr_spec_depth, pkt.cc_threshold, pkt.p0_key_max)
}

func (TraceOnETMv4) String() string {
	return "Trace On"
}

func (pkt TimestampETMv4) String() string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("Timestamp: 0x%x", pkt.timestamp))

	if pkt.cycle_count_valid {
		buffer.WriteString(fmt.Sprintf(" Cycle Count: 0x%x", pkt.cycle_count))
	}

	return buffer.String()
}
