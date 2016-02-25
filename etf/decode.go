package etf

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	log "github.com/Sirupsen/logrus"
)

const recordLen = 16
const lastByteRecord = recordLen - 1
const secondLastByte = lastByteRecord - 1

// NewDecoder stream parses a raw Embedded Trace FIFO format binary dump into
// only ETM trace for a specific stream.
func NewDecoder(in io.Reader) (map[uint64]string, error) {
	log.Debugln("Creating new ETF Decoder")

	// Map trace IDs to file pointers.  It'll be up to the caller to unlink
	// the unnecessary files.
	files := make(map[uint64]*os.File)
	// Filename map (will actually be returned to the caller)
	fn := make(map[uint64]string)

	// Defer closing each file we create. Caller must open the one of interest.
	defer func() {
		for i := range files {
			files[i].Close()
		}
	}()

	buf := make([]byte, recordLen)
	var curID uint64 // Current ID in the trace (may not be ours...)
	var i uint

	curID = 0

	for {
		n, err := io.ReadAtLeast(in, buf, recordLen)

		if err == io.ErrUnexpectedEOF || err == io.ErrShortBuffer {
			return nil, fmt.Errorf("Error received reading input file: %q", err)
		} else if n == 0 {
			break
		}

		log.Debugf("Read %d bytes, current ID: %d", n, curID)

		for i = 0; i < secondLastByte; i += 2 {
			aux := buf[lastByteRecord] >> (i / 2) & 1
			log.Debugf("buf[%0d]=%#v buf[%0d]=%#v buf[15]=%#v aux=%#v", i, buf[i], i+1, buf[i+1], buf[lastByteRecord], aux)
			if buf[i]&1 == 0 { // Data mode
				fn[curID] = makeTempFile(files, curID)
				data := []byte{(buf[i] & 0xfe) | ((buf[lastByteRecord] >> (i / 2)) & 1)}

				files[curID].Write(data)
				files[curID].Write([]byte{buf[i+1]})

				log.Debugf("Data mode, writing byte: %#v and %#v ID %d", data[0], buf[i+1], curID)
			} else if buf[i]&1 == 1 && aux == 0 { // bit[0] set, new ID immediately
				oldID := curID
				byteID := (buf[i] >> 1) & 0x7f
				curID, _ = binary.Uvarint([]byte{byteID})
				log.Debugf("ID update %d -> %d", oldID, curID)

				fn[curID] = makeTempFile(files, curID)
				files[curID].Write([]byte{buf[i+1]})

				log.Debugf("New ID immediately, writing byte: %#v ID %d", buf[i+1], curID)
			} else if buf[i]&1 == 1 && aux == 1 { // Update with new ID
				oldID := curID
				fn[curID] = makeTempFile(files, curID)
				files[curID].Write([]byte{buf[i+1]})

				log.Debugf("New ID, writing byte: %#v ID %d", buf[i+1], curID)
				byteID := (buf[i] >> 1) & 0x7f
				curID, _ = binary.Uvarint([]byte{byteID})

				log.Debugf("ID update %d -> %d", oldID, curID)
			} else {
				log.Errorln("Not sure what to do with this byte[%d]=%#v byte[%d]=%#v", i, buf[i], lastByteRecord, buf[lastByteRecord])
			}
		}
		if buf[secondLastByte]&1 == 1 { // Update ID
			oldID := curID
			byteID := (buf[secondLastByte] >> 1) & 0x7f
			curID, _ = binary.Uvarint([]byte{byteID})
			log.Debugf("ID update %d -> %d", oldID, curID)
			fn[curID] = makeTempFile(files, curID)
		} else {
			data := []byte{(buf[secondLastByte] & 0xfe) | (buf[lastByteRecord]>>7)&1}
			log.Debugf("Writing byte 14: %#v ID %d", data[0], curID)
			files[curID].Write(data)
		}
	}
	return fn, nil
}

func makeTempFile(files map[uint64]*os.File, id uint64) string {
	if files[id] == nil {
		var err error
		files[id], err = ioutil.TempFile("", fmt.Sprintf("etm-etf%d-", id))
		if err != nil {
			log.Errorf("Failed to create a temp file: %q", err)
		}
	}
	return files[id].Name()
}
