package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sarc/etm-decode/trace_packets_v4"

	log "github.com/Sirupsen/logrus"
)

var VERSION string
var BUILD_DATE string

var (
	debug         = flag.Bool("debug", false, "Debug logging.")
	etfMode       = flag.Bool("etf", false, "Input file is a binary ETF trace dump.")
	noEtfSync     = flag.Bool("noetfsync", true, "Input ETF binary lacks a frame sync.")
	etfEtmId      = flag.Int("id", 0, "Trace ID for ETM traffic to parse in ETF mode.")
	dbgDisIdCheck = flag.Bool("disidchk", false, "Disable ETF trace ID checks.")
	keepTmp       = flag.Bool("keeptmpbin", false, "Keep temporary ETF->ETM file.")
)

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s version %s\n", os.Args[0], VERSION)
		fmt.Fprintf(os.Stderr, "build %s\n", BUILD_DATE)
		fmt.Fprintln(os.Stderr, "usage:")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()

	if len(args) == 0 {
		log.Fatal("Not enough arguments, need a /path/to/file")
	}

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	filename := args[0]

	fmt.Println("Filename:", filename)

	var tmp *os.File
	var err error

	file, err := os.Open(filename)
	defer file.Close()

	if err != nil {
		log.Fatal(err)
	}

	if *etfMode {
		log.Println("Parsing input as ETF trace storage format.")
		// Input file needs to be parsed into raw ETM trace first
		tmp, err = ioutil.TempFile("", "etmv4-decoder")

		parseEtfToEtm(*etfEtmId, file, tmp)

		_, err = tmp.Seek(0, 0)
		if err != nil {
			fmt.Errorf("Error trying to seek backwards on temp file: %q", err)
		}
		file = tmp
	}

	log.Debugln("Synchronizing trace stream.  Looking for Async")
	// Sync trace stream; search for consecutive bytes of 00 (at least 11) followed by 80
	async_byte_count := 0
	for {
		b := make([]byte, 1)
		_, err := file.Read(b)

		if err != nil {
			log.Fatal(err)
		}

		if *debug {
			log.Printf("Current byte: %x\n", b)
		}
		if async_byte_count < 11 && b[0] == 0x00 {
			async_byte_count++
		} else if async_byte_count == 11 && b[0] == 0x80 {
			// Trace unit synchronized
			break
		} else {
			async_byte_count = 0
		}
	}
	trace_start_pos, err := file.Seek(0, os.SEEK_CUR)
	if *debug {
		log.Println("Trace unit synchronized at fpos ", trace_start_pos)
	}

	// Seek backwards to the beginning of ASYNC
	_, err = file.Seek(trace_start_pos-12, os.SEEK_SET)
	if err != nil {
		log.Fatal(err)
	}
	input := bufio.NewReader(file)

	for {
		header, err := input.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		pkt := etmv4_trace_packets.DecodePacket(header, input)
		if pkt != nil {
			fmt.Println(pkt.String())
		} else {
			log.Printf("WARN: Dropped byte 0x%x\n", header)
		}
	}
	if tmp != nil && !*keepTmp {
		os.Remove(tmp.Name())
	}
}

func parseEtfToEtm(id int, in *os.File, out *os.File) {
	var err error
	buf := make([]byte, 16)
	var curId uint64 // Current ID in the trace (may not be ours...)
	var compId uint64
	var i uint

	compId = uint64(id)
	curId = 0

	log.Debugf("compId: %v curId: %v", compId, curId)

	for err == nil {
		n, err := io.ReadAtLeast(in, buf, 16)

		if err == io.ErrUnexpectedEOF || err == io.ErrShortBuffer {
			fmt.Errorf("Error received reading input file: %q", err)
		} else if n == 0 {
			break
		}

		log.Debugf("Read %d bytes, current ID: %d", n, curId)

		for i = 0; i < 14; i += 2 {
			aux := buf[15] >> (i / 2) & 1
			log.Debugf("buf[%0d]=%#v buf[%0d]=%#v buf[15]=%#v aux=%#v", i, buf[i], i+1, buf[i+1], buf[15], aux)
			if buf[i]&1 == 0 { // Data mode
				if curId == compId || *dbgDisIdCheck {
					data := []byte{(buf[i] & 0xfe) | ((buf[15] >> (i / 2)) & 1)}
					out.Write(data)
					out.Write([]byte{buf[i+1]})
					log.Debugf("Data mode, writing byte: %#v and %#v ID %d", data[0], buf[i+1], curId)
				}
			} else if buf[i]&1 == 1 && aux == 0 { // bit[0] set, new ID immediately
				oldId := curId
				byteId := (buf[i] >> 1) & 0x7f
				curId, _ = binary.Uvarint([]byte{byteId})
				log.Debugf("ID update %d -> %d", oldId, curId)
				if curId == compId || *dbgDisIdCheck {
					out.Write([]byte{buf[i+1]})
					log.Debugf("New ID immediately, writing byte: %#v ID %d", buf[i+1], curId)
				}
			} else if buf[i]&1 == 1 && aux == 1 { // Update with new ID
				oldId := curId
				// Byte 1 corresponds to the old ID
				if curId == compId || *dbgDisIdCheck {
					out.Write([]byte{buf[i+1]})
					log.Debugf("New ID, writing byte: %#v ID %d", buf[i+1], curId)
				}
				byteId := (buf[i] >> 1) & 0x7f
				curId, _ = binary.Uvarint([]byte{byteId})
				log.Debugf("ID update %d -> %d", oldId, curId)
			} else {
				log.Errorln("Not sure what to do with this byte[%d]=%#v byte[15]=%#v", i, buf[i], buf[15])
			}
		}
		if buf[14]&1 == 1 { // Update ID
			oldId := curId
			byteId := (buf[14] >> 1) & 0x7f
			curId, _ = binary.Uvarint([]byte{byteId})
			log.Debugf("ID update %d -> %d", oldId, curId)
		} else if curId == compId || *dbgDisIdCheck {
			data := []byte{(buf[14] & 0xfe) | (buf[15]>>7)&1}
			log.Debugf("Writing byte 14: %#v ID %d", data[0], curId)
			out.Write(data)
		}
	}
}
