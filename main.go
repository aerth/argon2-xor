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

	// get CLI flags
	var (
		saltSize    = 1024
		outflag     = flag.String("out", "-", "output file")
		timeFlag    = flag.Int("t", 100, "argon2 time parameter")
		memFlag     = flag.Int("m", 10000, "argon2 mem parameter")
		threadFlag  = flag.Int("p", 1, "argon2 thread/parallelism parameter")
		decryptFlag = flag.Bool("d", false, "decrypt mode")
	)
	flag.IntVar(&saltSize, "saltlen", saltSize, "use custom salt size")
	flag.Parse()

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
	if len(buffer) == 0 {
		log.Fatalln("input file is empty")
	}

	// set key length equal to input buffer size
	keylen = len(buffer)

	// subtract saltlen and MAC size if decrypting
	if *decryptFlag {
		keylen -= saltSize + macBlockSize
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
	var mac = hmac.New(sha256.New, hashedKey)

	if *decryptFlag {
		// decrypt buffer
		XOR(buffer[saltSize+mac.Size():], hashedKey)

		// compare HMAC
		mac.Write(buffer[saltSize+mac.Size():])
		if !hmac.Equal(buffer[saltSize:saltSize+mac.Size()], mac.Sum(nil)) {
			log.Fatalf("has been tampered with, MAC check failed: MAC=%02x", buffer[saltSize:saltSize+mac.Size()])
		}

		// write only the buffer to output
		io.Copy(out, bytes.NewReader(buffer[saltSize+mac.Size():]))
		return
	}

	// write salt, MAC, and encrypted buffer
	out.Write(salt)
	mac.Write(buffer)
	io.Copy(out, bytes.NewReader(mac.Sum(nil)))
	XOR(buffer, hashedKey)
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
