package main

import (
	"bytes"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	log.SetFlags(0)
	var outflag = flag.String("out", "-", "output file")
	var verboseFlag = flag.Bool("v", false, "verbose output to stderr")
	flag.Parse()
	if !*verboseFlag {
		log.SetOutput(ioutil.Discard)
	}
	var (
		input    []byte
		password []byte
		salt     []byte = []byte("version 1.2")
		time     uint32 = 100
		mem      uint32 = 10000
		threads  uint8  = 1
		args            = flag.Args()
		err      error
	)
	if len(args) != 1 {
		flag.PrintDefaults()
		log.Fatalln("need input file as only argument")
	}

	input, err = ioutil.ReadFile(args[0])
	if err != nil {
		log.Fatalln(err)
	}
	var keylen int = len(input)
	if terminal.IsTerminal(syscall.Stdin) {
		log.Printf("Password: (will NOT echo)")
		password, err = terminal.ReadPassword(0)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		log.Println("reading password from stdin")
		buf := &bytes.Buffer{}
		io.Copy(buf, os.Stdin)
		password = buf.Bytes()
	}
	log.Println("\nLoading... please wait.")
	log.Printf("Hash: %02x\n", argon2.IDKey(password, salt, time, mem, threads, 16))

	var b = argon2.IDKey(password, salt, time, mem, threads, uint32(keylen))

	for i := 0; i < keylen; i++ {
		b[i] = b[i] ^ input[i]
	}
	var out = os.Stdout
	if *outflag != "-" && *outflag != "" {
		out, err = os.OpenFile(*outflag, os.O_CREATE|os.O_RDWR, 0600)
	}
	io.Copy(out, bytes.NewReader(b))
}
