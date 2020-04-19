# argon2-xor

simple XOR stream with HMAC and random salt

Using the variable output length of the Argon2id hash function, we are able to derive a key to use with XOR stream cipher.

We generate a random salt, Encrypt-then-MAC, and save to a file (or stdout).

To decrypt, we extract the salt and MAC, hash the password (with given salt), and XOR the rest of the file.

Note: This is a toy program, and hasn't been vetted by cryptographers or security professionals.

## Basic Usage
#### Encryption
```
argon2-xor -out file.enc plaintext.txt
```
#### Decryption
```
argon2-xor -d -out plaintext.txt file.enc
```
#### CLI Flags
```
  -d	decrypt mode
  -hmac string
    	hash function for use with HMAC: sha256, sha384, or sha512 (default "sha512")
  -m int
    	argon2 mem parameter (default 10000)
  -out string
    	output file (default "stdout")
  -p int
    	argon2 thread/parallelism parameter (default 1)
  -saltlen int
    	use custom salt size (default 1024)
  -t int
    	argon2 time parameter (default 100)
```