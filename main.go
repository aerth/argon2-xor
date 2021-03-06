// Copyright 2020 aerth <aerth@riseup.net>
// Released under the GPLv3 license

// argon2-xor command encrypts and decrypts files using a simple XOR stream with argon2 variable length output hash
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
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

var version = "1.0.0"
var sourceURL = "https://github.com/aerth/argon2-xor"

func main() {
	log.SetFlags(0)

	// get CLI flags
	var (
		saltSize    = 1024
		outflag     = flag.String("out", "stdout", "output file")
		timeFlag    = flag.Int("t", 1, "argon2 time parameter")
		memFlag     = flag.Int("m", 1024*128, "argon2 mem parameter")
		threadFlag  = flag.Int("p", 4, "argon2 thread/parallelism parameter")
		decryptFlag = flag.Bool("d", false, "decrypt mode")
		macHashFlag = flag.String("hmac", "sha512", "hash function for use with HMAC: sha256, sha384, or sha512")
		showVersion = flag.Bool("version", false, "show version and exit")
		hashFn      = sha512.New
	)
	flag.IntVar(&saltSize, "saltlen", saltSize, "use custom salt size")
	flag.Parse()
	if *showVersion {
		log.Printf("argon2-xor v%s\nsource code: %s", version, sourceURL)
		os.Exit(0)
	}
	switch *macHashFlag {
	case "sha256":
		hashFn = sha256.New
	case "sha384":
		hashFn = sha512.New384
	case "sha512":
		hashFn = sha512.New
	default:
		log.Fatalln("unsupported HMAC hash function:", *macHashFlag)
	}

	// setup
	var (
		buffer   []byte
		password []byte
		salt     []byte
		time     = uint32(*timeFlag)
		mem      = uint32(*memFlag)
		threads  = uint8(*threadFlag)
		keylen   int
		err      error
		out      = os.Stdout
		args     = flag.Args()
	)

	// require input file
	if len(args) != 1 {
		log.Printf("argon2-xor v%s\nsource code: %s", version, sourceURL)
		flag.PrintDefaults()
		log.Fatalln("need input file as only argument")
	}

	// setup output file if not stdout
	if *outflag != "-" && *outflag != "" && *outflag != "stdout" {
		out, err = os.OpenFile(os.ExpandEnv(*outflag), os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// read input (plaintext, or if decrypting, mac+cyphertext)
	buffer, err = ioutil.ReadFile(os.ExpandEnv(args[0]))
	if err != nil {
		log.Fatalln(err)
	}
	if len(buffer) == 0 {
		log.Fatalln("input file is empty")
	}

	// set key length equal to input buffer size
	keylen = len(buffer)

	// subtract saltlen and MAC size if decrypting
	if *decryptFlag {
		keylen -= saltSize + hmac.New(hashFn, []byte{}).Size()
	}

	// get passwd from stdin or terminal
	password, err = getPasswd()
	if err != nil {
		log.Fatalln(err)
	}

	println("Loading... please wait.")

	// get salt
	if *decryptFlag {
		salt = buffer[:saltSize]
	} else {
		salt = make([]byte, saltSize)
		rand.Read(salt)
	}

	// get key from password
	var hashedKey = argon2.IDKey(password, salt, time, mem, threads, uint32(keylen))
	var mac = hmac.New(hashFn, hashedKey)

	if *decryptFlag {

		// compare HMAC
		mac.Write(buffer[saltSize+mac.Size():])
		if !hmac.Equal(buffer[saltSize:saltSize+mac.Size()], mac.Sum(nil)) {
			log.Fatalln("Encrypted file has been tampered with, MAC check failed")
		}
		// decrypt buffer
		XOR(buffer[saltSize+mac.Size():], hashedKey)

		// write only the buffer to output
		io.Copy(out, bytes.NewReader(buffer[saltSize+mac.Size():]))
		return
	}

	// write salt, MAC, and encrypted buffer
	XOR(buffer, hashedKey)
	out.Write(salt)
	mac.Write(buffer)
	io.Copy(out, bytes.NewReader(mac.Sum(nil)))
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
func getPasswd() ([]byte, error) {
	if terminal.IsTerminal(syscall.Stdin) {
		println("Password: (will NOT echo)")
		return terminal.ReadPassword(0)
	}
	log.Println("reading password from stdin")
	buf := &bytes.Buffer{}
	io.Copy(buf, os.Stdin)
	return buf.Bytes(), nil
}
