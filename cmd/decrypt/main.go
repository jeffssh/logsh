package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/jeffssh/logsh/pkg/utils"
)

var delimiter string = "delimiter"

//go:embed encryption.key
var keyBytes []byte

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: decrypt ./path/to/file")
		return
	}

	filePath := os.Args[1]
	fileBytes, err := ioutil.ReadFile(filePath)
	errCheck(err)

	// extract base64 encoded encrypted output
	i := bytes.Index(fileBytes, []byte(delimiter))
	if i == -1 {
		fmt.Printf("Delimiter'%s' not found in %s\n", delimiter, filePath)
	}
	fileBytes = fileBytes[i+len(delimiter)+1:]
	i = bytes.Index(fileBytes, []byte(delimiter))
	if i == -1 {
		fmt.Printf("Second delimiter '%s' not found in %s\n", delimiter, filePath)
	}
	b64EncryptedBytes := fileBytes[:i-1]
	encryptedBytes := make([]byte, base64.StdEncoding.DecodedLen(len(b64EncryptedBytes)))
	sizeOfEncryptedBytes, err := b64.StdEncoding.Decode(encryptedBytes, b64EncryptedBytes)
	errCheck(err)
	encryptedBytes = encryptedBytes[:sizeOfEncryptedBytes]
	encryptionKeyLengthBytes, encryptedBytes := encryptedBytes[:4], encryptedBytes[4:]
	encryptionKeyLength := binary.LittleEndian.Uint32(encryptionKeyLengthBytes)
	encryptedAesKey, encryptedCmdOutputBytes := encryptedBytes[:encryptionKeyLength], encryptedBytes[encryptionKeyLength:]

	// decrypt prepended aes key
	keyPemBlock, _ := pem.Decode(keyBytes)
	if keyPemBlock == nil || keyPemBlock.Bytes == nil {
		errCheck(errors.New("could not read key pem file"))
	}
	decryptionKey, err := x509.ParsePKCS8PrivateKey(keyPemBlock.Bytes)
	errCheck(err)

	// Decrypt output
	aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, decryptionKey.(*rsa.PrivateKey), encryptedAesKey)
	errCheck(err)

	//fmt.Print(string(outputBytes))
	cmdOutput := utils.AesDecrypt(encryptedCmdOutputBytes, aesKey)
	fmt.Println(string(cmdOutput))
}

func errCheck(err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
}
