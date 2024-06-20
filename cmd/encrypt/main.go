package main

import (
	_ "embed"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/jeffssh/logsh/pkg/utils"
)

//go:embed embed.key
var embeddedAesKeyBytes []byte

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: encrypt ./path/to/srcFile ./path/to/dstFile")
		return
	}

	// os.Args[0] is the program name, so os.Args[1] is the first provided argument
	srcFilePath := os.Args[1]
	dstFilePath := os.Args[2]
	fileBytes, err := ioutil.ReadFile(srcFilePath)
	errCheck(err)
	// encrypt script and path with shared aes key to be embedded
	ciphertextBytes := utils.AesEncrypt(fileBytes, embeddedAesKeyBytes)
	//fmt.Printf("Aes encryption: %s\n", string(ciphertextBytes))
	// plaintextBytes := utils.AesDecrypt(ciphertextBytes, embeddedAesKeyBytes)
	// fmt.Printf("Aes decryption: %s\n", string(plaintextBytes))

	dstFile, err := os.Create(dstFilePath)
	errCheck(err)
	defer dstFile.Close()
	_, err = dstFile.Write(ciphertextBytes)
	errCheck(err)
	// Load embedded aes key
	// ciphertextBytes := utils.AesEncrypt([]byte("Here is a string...."), embeddedAesKeyBytes)
	// fmt.Printf("Aes encryption: %s\n", string(ciphertextBytes))
	// plaintextBytes := utils.AesDecrypt(ciphertextBytes, embeddedAesKeyBytes)
	// fmt.Printf("Aes decryption: %s\n", string(plaintextBytes))
}

func errCheck(err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
}
