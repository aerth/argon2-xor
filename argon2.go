package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"flag"
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
		outflag     = flag.String("out", "-", "output file")
		verboseFlag = flag.Bool("v", false, "verbose output to stderr")
		timeFlag    = flag.Int("t", 100, "argon2 time parameter")
		memFlag     = flag.Int("m", 10000, "argon2 mem parameter")
		threadFlag  = flag.Int("p", 1, "argon2 thread/parallelism parameter")
		decryptFlag = flag.Bool("d", false, "decrypt mode")
		disableHMAC = flag.Bool("nomac", false, "disable HMAC support")
	)
	flag.Parse()
	if !*verboseFlag {
		log.SetOutput(ioutil.Discard)
	}

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
		log.SetOutput(os.Stderr)
		log.Fatalln("need input file as only argument")
	}

	// setup output file if not stdout
	if *outflag != "-" && *outflag != "" && *outflag != "stdout" {
		log.Println("Opening file for writing:", *outflag)
		out, err = os.OpenFile(*outflag, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			log.SetOutput(os.Stderr)
			log.Fatalln(err)
		}
	}

	// read input (plaintext, or if decrypting, mac+cyphertext)
	buffer, err = ioutil.ReadFile(args[0])
	if err != nil {
		log.SetOutput(os.Stderr)
		log.Fatalln(err)
	}
	log.Println("read file:", args[0])
	if len(buffer) == 0 {
		log.SetOutput(os.Stderr)
		log.Fatalln("input file is empty")
	}

	keylen = len(buffer)
	if *decryptFlag && useHmac {
		keylen -= macBlockSize
	}

	log.Println("key len:", keylen, "input len:", len(buffer))

	// get password
	if terminal.IsTerminal(syscall.Stdin) {
		println("Password: (will NOT echo)")
		password, err = terminal.ReadPassword(0)
		if err != nil {
			log.SetOutput(os.Stderr)
			log.Fatalln(err)
		}
	} else {
		log.Println("reading password from stdin")
		buf := &bytes.Buffer{}
		io.Copy(buf, os.Stdin)
		password = buf.Bytes()
	}

	println("Loading... please wait.")

	// print a quick hash of the password for comparison (TODO: remove)
	if *verboseFlag {
		log.Printf("Hash: %02x\n", argon2.IDKey(password, salt, time, mem, threads, 16))
	}

	// hash password
	const saltSize = 32
	if *decryptFlag {
		salt = buffer[:saltSize]
		buffer = buffer[saltSize:]
		keylen -= saltSize
	} else {
		salt = make([]byte, 32)
		rand.Read(salt)
		out.Write(salt)
	}
	var hashedKey = argon2.IDKey(password, salt, time, mem, threads, uint32(keylen))

	if useHmac {
		mac := hmac.New(sha256.New, hashedKey)
		if *decryptFlag {
			var givenMac = buffer[:macBlockSize]
			buffer = buffer[macBlockSize:]
			XOR(buffer, hashedKey)
			mac.Write(buffer)
			if !hmac.Equal(givenMac, mac.Sum(nil)) {
				log.SetOutput(os.Stderr)
				log.Fatalln("has been tampered with, MAC check failed")
			}
		} else {
			mac.Write(buffer)
			macResult := mac.Sum(nil)
			log.Printf("MAC: %v 0x%02x", len(macResult), macResult)
			io.Copy(out, bytes.NewReader(macResult))
			XOR(buffer, hashedKey)
		}
	} else {
		// just plain xor, no hmac
		XOR(buffer, hashedKey)
	}

	// copy xor'd bytes to output
	io.Copy(out, bytes.NewReader(buffer))
}
func XOR(output, input []byte) {
	// XOR cipher stream
	if len(output) != len(input) {
		panic("key len != input len")
	}
	for i := 0; i < len(input); i++ {
		output[i] ^= input[i]
	}
}

// ValidMAC reports whether messageMAC is a valid HMAC tag for message.
func ValidMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
