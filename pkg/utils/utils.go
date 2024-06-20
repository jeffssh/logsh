package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func AesEncrypt(plaintextBytes, keyBytes []byte) (ciphertextBytes []byte) {

	//Since the key is in string, we need to convert decode it to bytes
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	emptyIv := make([]byte, block.BlockSize())
	aesCBC := cipher.NewCBCEncrypter(block, emptyIv)
	if err != nil {
		panic(err.Error())
	}

	// //Create a nonce. Nonce should be from GCM
	// nonce := make([]byte, aesGCM.NonceSize())
	// if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
	// 	panic(err.Error())
	// }

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	//ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	pad := block.BlockSize() - len(plaintextBytes)%block.BlockSize()
	padBytes := bytes.Repeat([]byte{byte(pad)}, pad)
	paddedPlaintextBytes := append(plaintextBytes, padBytes...)
	ciphertextBytes = make([]byte, len(paddedPlaintextBytes))
	aesCBC.CryptBlocks(ciphertextBytes, paddedPlaintextBytes)
	return
}

func AesDecrypt(ciphertextBytes, keyBytes []byte) (plaintextBytes []byte) {

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err.Error())
	}

	//Create a new CBC
	emptyIv := make([]byte, block.BlockSize())
	// Extract the IV (first 16 bytes) and ciphertext
	//iv := encryptedBytes[:aes.BlockSize]
	aesCBC := cipher.NewCBCDecrypter(block, emptyIv)

	//Get the nonce size
	plaintextBytes = make([]byte, len(ciphertextBytes))
	aesCBC.CryptBlocks(plaintextBytes, ciphertextBytes)
	// remove padding
	padding := plaintextBytes[len(plaintextBytes)-1]
	plaintextBytes = plaintextBytes[:len(plaintextBytes)-int(padding)]
	return
}
