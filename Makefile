argon2-xor: *.go
	go build -o $@
test: argon2-xor
	echo 'password' | ./argon2-xor -v -out argon2-xor.enc ./argon2-xor
	echo 'password' | ./argon2-xor -d -v -out argon2-xor-copy ./argon2-xor.enc
	sha256sum *-xor*
clean:
	rm -rf argon2-xor argon2-xor.enc
