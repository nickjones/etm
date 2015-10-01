package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sarc/etm-decode/trace_packets_v4"
)

func main() {
	// hex_mode := flag.Bool("hex", false, "Read file as ASCII hex.")
	filename := flag.String("input", "dump.dat", "Input file to read.")

	flag.Parse()

	// fmt.Println("Hex mode:", *hex_mode)
	fmt.Println("Filename:", *filename)

	file, err := os.Open(*filename)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Synchronizing trace stream.  Looking for Async")
	// Sync trace stream; search for consecutive bytes of 00 (at least 11) followed by 80
	async_byte_count := 0
	for {
		b := make([]byte, 1)
		_, err := file.Read(b)

		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Current byte: %x\n", b)
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
	log.Println("Trace unit synchronized at fpos ", trace_start_pos)

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
}
