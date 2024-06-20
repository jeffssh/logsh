package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/jeffssh/logsh/pkg/utils"
)

var delimiter string = "delimiter"

//go:embed encryption.cer
var certBytes []byte

//go:embed encryption.key
var certKeyBytes []byte

//go:embed decryption.key
var keyBytes []byte

//go:embed k
var encryptedAesKeyBytes []byte

//go:embed p
var encryptedBinPathBytes []byte

//go:embed s
var encryptedScriptBytes []byte

func main() {
	// Load certificate and public key
	certPemBlock, _ := pem.Decode(certBytes)
	if certPemBlock == nil || certPemBlock.Bytes == nil {
		errCheck(errors.New("could not read cert pem file"))
	}
	cert, err := x509.ParseCertificate(certPemBlock.Bytes)
	errCheck(err)
	encryptionKey := cert.PublicKey.(*rsa.PublicKey)
	errCheck(err)

	// Load private key
	keyPemBlock, _ := pem.Decode(keyBytes)
	if keyPemBlock == nil || keyPemBlock.Bytes == nil {
		errCheck(errors.New("could not read key pem file"))
	}
	decryptionKey, err := x509.ParsePKCS8PrivateKey(keyPemBlock.Bytes)
	errCheck(err)

	// Decrypt aes key
	aesKeyBytes, err := rsa.DecryptPKCS1v15(rand.Reader, decryptionKey.(*rsa.PrivateKey), encryptedAesKeyBytes)
	errCheck(err)
	// Decrypt script and interpreter path
	scriptBytes := utils.AesDecrypt(encryptedScriptBytes, aesKeyBytes)
	binPathBytes := utils.AesDecrypt(encryptedBinPathBytes, aesKeyBytes)
	scriptReader := bytes.NewReader(scriptBytes)
	binPath := string(binPathBytes)

	// Run command
	cmd := exec.Command(binPath)
	cmd.Stdin = scriptReader
	cmdOutput, err := cmd.CombinedOutput()
	errCheck(err)

	// generate new AES key for encrypted output
	newAesKeyBytes := make([]byte, len(aesKeyBytes))
	_, err = rand.Read(newAesKeyBytes)
	errCheck(err)
	// Encrypt and encode the output
	encryptedNewAesKeyBytes, err := rsa.EncryptPKCS1v15(rand.Reader, encryptionKey, newAesKeyBytes)
	errCheck(err)
	encryptedKeyLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(encryptedKeyLength, uint32(len(encryptedNewAesKeyBytes)))
	encryptedNewAesKeyBytesAndLength := append(encryptedKeyLength, encryptedNewAesKeyBytes...)
	encryptedCmdOutputBytes := utils.AesEncrypt(cmdOutput, newAesKeyBytes)
	b64EncryptedOutput := b64.StdEncoding.EncodeToString(append(encryptedNewAesKeyBytesAndLength, []byte(encryptedCmdOutputBytes)...))
	delimitedOutput := fmt.Sprintf("%s\n%s\n%s", delimiter, b64EncryptedOutput, delimiter)

	// write parsable output to stdout and stderr
	fmt.Println(delimitedOutput)
	fmt.Fprintln(os.Stderr, delimitedOutput)
}

func errCheck(err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
}
