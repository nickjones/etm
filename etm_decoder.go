package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	etf "github.com/nickjones/etm/etf"
	pkts "github.com/nickjones/etm/tracepkts"
)

// Build semantic version
var VERSION string

// Date of build
var BUILD_DATE string

var (
	debug         = flag.Bool("debug", false, "Debug logging.")
	etfMode       = flag.Bool("etf", false, "Input file is a binary ETF trace dump.")
	noEtfSync     = flag.Bool("noetfsync", true, "Input ETF binary lacks a frame sync.")
	etfEtmID      = flag.Int("id", 0, "Trace ID for ETM traffic to parse in ETF mode.")
	dbgDisIDCheck = flag.Bool("disidchk", false, "Disable ETF trace ID checks.")
	keepTmp       = flag.Bool("keeptmpbin", false, "Keep temporary ETF->ETM file.")
)

type ETMv4AddressStackElement struct {
	address uint64
	is      uint8
}

type ETMv4AddressStack struct {
	entries []ETMv4AddressStackElement
}


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

	var err error

	file, err := os.Open(filename)
	defer file.Close()

	if err != nil {
		log.Fatal(err)
	}

	if *etfMode {
		log.Println("Parsing input as ETF trace storage format.")
		// Input file needs to be parsed into raw ETM trace first
		traceFiles, err := etf.NewDecoder(file)

		// Open the temp file of interest to the user
		traceID := uint64(*etfEtmID)
		if len(traceFiles[traceID]) > 0 {
			file, err = os.Open(traceFiles[traceID])
			if err != nil {
				log.Errorf("Error opening temp file from ETF parsing: %q", err)
			}
		} else {
			log.Errorf("Unable to find ETF trace ID %d", *etfEtmID)
		}

		defer file.Close()
		// ETF parsing creates temp files for each ID, remove them all (eventually)
		if !*keepTmp {
			defer func() {
				for i := range traceFiles {
					os.Remove(traceFiles[i])
				}
			}()
		}
	}

	log.Debugln("Synchronizing trace stream.  Looking for Async")
	// Sync trace stream; search for consecutive bytes of 00 (at least 11) followed by 80
	asyncByteCnt := 0
	for {
		b := make([]byte, 1)
		_, err := file.Read(b)

		if err != nil {
			log.Fatal(err)
		}

		if *debug {
			log.Printf("Current byte: %x\n", b)
		}
		if asyncByteCnt < 11 && b[0] == 0x00 {
			asyncByteCnt++
		} else if asyncByteCnt == 11 && b[0] == 0x80 {
			// Trace unit synchronized
			break
		} else {
			asyncByteCnt = 0
		}
	}
	traceStartPos, err := file.Seek(0, os.SEEK_CUR)
	if *debug {
		log.Println("Trace unit synchronized at fpos ", traceStartPos)
	}

	// Seek backwards to the beginning of ASYNC
	_, err = file.Seek(traceStartPos-12, os.SEEK_SET)
	if err != nil {
		log.Fatal(err)
	}
	input := bufio.NewReader(file)

	var addr_stack ETMv4AddressStack

	for {
		header, err := input.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		pkt := pkts.DecodePacket(header, input)
		if pkt != nil {
			switch pkt.(type) {
			default:
				log.Println(pkt.String())

			case pkts.Long64bAddrETMv4:
				addr_pkt := pkt.(pkts.Long64bAddrETMv4)
				addr_stack.Push(addr_pkt.Address(), addr_pkt.IS())
				log.Println(pkt.String())

			case pkts.CompressedAddrETMv4:
				addr_pkt := pkt.(pkts.CompressedAddrETMv4)
				addr_base_elm := addr_stack.Get(0)
				addr := addr_pkt.AddrWithBase(addr_base_elm.address)
				addr_stack.Push(addr, addr_pkt.IS())
				log.Printf("IS%d Address = 0x%016x (Compressed %d-bit)\n", addr_pkt.IS(), addr, addr_pkt.Width())

			case pkts.ExactAddrETMv4:
				exact_pkt := pkt.(pkts.ExactAddrETMv4)
				entry_num, err := exact_pkt.Entry()
				if err != nil {
					log.Printf("WARN: failed parsing Exact Address Packet: %#v\n", err)
				}
				stack_elm := addr_stack.Get(entry_num)
				addr_stack.Push(stack_elm.address, stack_elm.is)
				log.Printf("IS%d Address = 0x%016x (Exact Match)\n", stack_elm.is, stack_elm.address)

			}
		} else {
			log.Printf("WARN: Dropped byte 0x%x\n", header)
		}
	}
}

func (s *ETMv4AddressStack) Push(rhs_address uint64, rhs_is uint8) {
	log.Debugf("Pushing addr=0x%016x is=%d\n", rhs_address, rhs_is)
	s.entries = append(s.entries, ETMv4AddressStackElement{address: rhs_address, is: rhs_is})
	for i, e := range s.entries {
		log.Debugf("Addr Stack %d: %#v\n", i, e)
	}
	s.Compact()
}

func (s *ETMv4AddressStack) Compact() {
	// Drop oldest address, trace analyzer is required to keep a certain depth
	if len(s.entries) > pkts.ADDR_COMP_STK_DEPTH {
		s.entries = s.entries[:len(s.entries)-1]
	}
}

func (s ETMv4AddressStack) Get(idx uint8) ETMv4AddressStackElement {
	if len(s.entries) < int(idx) {
		log.Printf("WARN: Address stack match with missing entry!")
		return ETMv4AddressStackElement{}
	}
	return s.entries[idx]
}
