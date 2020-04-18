TARGETDIR ?= /usr/local/bin/
argon2-xor: *.go
	go build -o $@
test: argon2-xor
	echo 'password' | ./argon2-xor -out argon2-xor.enc ./argon2-xor
	echo 'password' | ./argon2-xor -d -out argon2-xor-copy ./argon2-xor.enc
	sha256sum argon2-xor argon2-xor-copy
clean:
	rm -rf argon2-xor argon2-xor.enc argon2-xor-copy
install:
	install argon2-xor ${TARGETDIR}
.PHONY += clean
.PHONY += install
