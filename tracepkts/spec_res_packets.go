package tracepkts

import (
	"bufio"
	"fmt"
	"log"
)

type CommitETMv4 struct {
	*GenericTracePacketv4
	commit uint32
}

func DecodeCommit(header byte, reader *bufio.Reader) TracePacket {
	pkt := CommitETMv4{}
	for i := 0; ; i++ {
		commit_byte, err := reader.ReadByte()
		if err != nil {
			log.Println("Error reading stream decoding Commit.")
			return nil
		}

		pkt.commit |= uint32(commit_byte & 0x7f << uint(i*7))

		if commit_byte&0x80 == 0 {
			break
		}
	}
	return pkt
}

func (pkt CommitETMv4) String() string {
	return fmt.Sprintf("Commit %d", pkt.commit)
}
