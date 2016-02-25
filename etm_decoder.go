package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	log "github.com/Sirupsen/logrus"
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
			fmt.Println(pkt.String())
		} else {
			log.Printf("WARN: Dropped byte 0x%x\n", header)
		}
	}
}
