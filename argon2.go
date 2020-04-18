package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

const macBlockSize = 32

func main() {
	log.SetFlags(0)
	var (
		saltSize    = 16
		outflag     = flag.String("out", "-", "output file")
		timeFlag    = flag.Int("t", 100, "argon2 time parameter")
		memFlag     = flag.Int("m", 10000, "argon2 mem parameter")
		threadFlag  = flag.Int("p", 1, "argon2 thread/parallelism parameter")
		decryptFlag = flag.Bool("d", false, "decrypt mode")
		disableHMAC = flag.Bool("nomac", false, "disable HMAC support")
	)
	flag.IntVar(&saltSize, "saltlen", saltSize, "use custom salt size")
	flag.Parse()
	var (
		buffer   []byte
		password []byte
		salt     []byte
		time     = uint32(*timeFlag)
		mem      = uint32(*memFlag)
		threads  = uint8(*threadFlag)
		keylen   int
		err      error
	)

	var (
		out     = os.Stdout
		useHmac = !*disableHMAC
		args    = flag.Args()
	)

	if len(args) != 1 {
		flag.PrintDefaults()
		log.Fatalln("need input file as only argument")
	}

	// setup output file if not stdout
	if *outflag != "-" && *outflag != "" && *outflag != "stdout" {
		out, err = os.OpenFile(*outflag, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// read input (plaintext, or if decrypting, mac+cyphertext)
	buffer, err = ioutil.ReadFile(args[0])
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("read file:", args[0])
	if len(buffer) == 0 {
		log.Fatalln("input file is empty")
	}

	keylen = len(buffer)
	if *decryptFlag && useHmac {
		keylen -= macBlockSize
	}
	if *decryptFlag {
		keylen -= saltSize
	}

	// get password
	if terminal.IsTerminal(syscall.Stdin) {
		println("Password: (will NOT echo)")
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

	println("Loading... please wait.")
	// hash password
	if *decryptFlag {
		salt = buffer[:saltSize]
		buffer = buffer[saltSize:]
	} else {
		salt = make([]byte, saltSize)
		rand.Read(salt)
		out.Write(salt)
	}
	var hashedKey = argon2.IDKey(password, salt, time, mem, threads, uint32(keylen))

	if !useHmac {

		// just plain xor, no hmac
		XOR(buffer, hashedKey)

		// copy xor'd bytes to output
		io.Copy(out, bytes.NewReader(buffer))
		return
	}
	mac := hmac.New(sha256.New, hashedKey)
	if *decryptFlag {
		var givenMac = buffer[:macBlockSize]
		buffer = buffer[macBlockSize:]
		XOR(buffer, hashedKey)
		mac.Write(buffer)
		if !hmac.Equal(givenMac, mac.Sum(nil)) {
			log.Fatalln("has been tampered with, MAC check failed")
		}
	} else {
		mac.Write(buffer)
		macResult := mac.Sum(nil)
		io.Copy(out, bytes.NewReader(macResult))
		XOR(buffer, hashedKey)
	}
	// copy xor'd bytes to output
	io.Copy(out, bytes.NewReader(buffer))
}
func XOR(output, input []byte) {
	// XOR cipher stream
	if len(output) > len(input) {
		panic(fmt.Sprintf("key len is less than input len", len(output), len(input), len(output)-len(input)))
	}
	for i := 0; i < len(output); i++ {
		output[i] ^= input[i]
	}
}
