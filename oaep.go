package rsaoaep

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"
	"io"
	"os"
)

// OAEP define instance
type OAEP struct {
	hash   hash.Hash
	random io.Reader
}

// NewRSAOaep set attributes for an OAEP instance
//
// @param hash <Hash> hash function
// @return error
func NewRSAOaep(hash hash.Hash) *OAEP {
	oaep := &OAEP{}
	oaep.hash = hash
	oaep.random = rand.Reader

	return oaep
}

// Encrypt encrypts the given message with RSA-OAEP.
//
// @param publicKey <*rsa.PublicKey> public part of an RSA key
// @param message <[]byte> message to encrypt
// @param label <[]byte>
// @return ([]byte, error)
func (oaep *OAEP) Encrypt(publicKey *rsa.PublicKey, message []byte, label []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptOAEP(oaep.hash, oaep.random, publicKey, message, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return nil, err
	}

	return cipherText, nil
}

// Dencrypt dencrypts the given message with RSA-OAEP.
//
// @param privateKey <*rsa.PrivateKey> represents an RSA key
// @param label <[]byte> label parameter must match the value given when encrypting
// @return ([]byte, error)
func (oaep *OAEP) Dencrypt(privateKey *rsa.PrivateKey, cipherText []byte, label []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(oaep.hash, oaep.random, privateKey, cipherText, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		return nil, err
	}

	return plaintext, nil
}
