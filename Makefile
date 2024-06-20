BINPATH=/bin/bash
SCRIPTPATH=./script.sh
DELIMITER?=$(shell printf ==========`hexdump -vn16 -e'4/4 "%08X" 1 "\n"' /dev/urandom`==========)
DELIMITER:=${DELIMITER}
GOOS=
GOARCH=


all:
	make clean
	make embedded-files
	make build

end-to-end-test:
	make clean
	make all
	bash -c "./decrypt <(./logsh 2>&1)"

build-encrypt:
	go get ./...
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o . ./cmd/encrypt

build:
	go get ./...
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o . -ldflags "-X main.delimiter=$(DELIMITER)" ./cmd/decrypt
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o . -ldflags "-X main.delimiter=$(DELIMITER)" ./cmd/logsh

embedded-files:
	mkdir cert 2>/dev/null
	
	bash -c "openssl req -x509 -new -newkey rsa:2048 -nodes -keyout cert/encryption.key -out cert/encryption.cer -subj \"/O=logsh/\" -extensions SAN -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf \"\n[ SAN ]\nsubjectAltName=IP:127.0.0.1\n\"))"
	bash -c "openssl x509 -pubkey -noout -in ./cert/encryption.cer -out cert/encryption_public_key.key"


	bash -c "openssl req -x509 -new -newkey rsa:2048 -nodes -keyout cert/decryption.key -out cert/decryption.cer -subj \"/O=logsh/\" -extensions SAN -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf \"\n[ SAN ]\nsubjectAltName=IP:127.0.0.1\n\"))"
	bash -c "openssl x509 -pubkey -noout -in ./cert/decryption.cer -out cert/decryption_public_key.key"

	dd if=/dev/urandom of=cert/embed.key bs=32 count=1
	cp cert/embed.key cmd/encrypt/
	make build-encrypt

	bash -c "openssl rsautl -encrypt -in cert/embed.key -out cmd/logsh/k -inkey ./cert/decryption_public_key.key -pubin"

	bash -c "./encrypt $(SCRIPTPATH) ./cmd/logsh/s"
	bash -c "./encrypt <(printf $(BINPATH)) ./cmd/logsh/p"
	#bash -c "openssl enc -aes-256-cbc -in $(SCRIPTPATH) -out cmd/logsh/s -k file:cert/aes.key -iv 0 -nosalt"
	#bash -c "openssl enc -aes-256-cbc -in <(printf $(BINPATH)) -out cmd/logsh/p -kfile cert/aes.key"

	
	cp cert/* cmd/logsh/
	cp cert/* cmd/decrypt/


	
clean:
	rm -f logsh
	rm -f encrypt
	rm -f decrypt
	rm -rf cert
	rm -f cmd/encrypt/*.cer
	rm -f cmd/encrypt/*.key
	rm -f cmd/decrypt/*.cer
	rm -f cmd/decrypt/*.key
	rm -f cmd/logsh/*.cer
	rm -f cmd/logsh/*.key
	rm -f cmd/logsh/p
	rm -f cmd/logsh/s
	rm -f cmd/logsh/k
	