package rsaoaep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestEncryptAndDecrypt(t *testing.T) {
	message := "Love bitcoin!"
	label := []byte("bitcoin")
	keySize := 1024
	if testing.Short() {
		keySize = 128
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Fatal(err)
	}

	oaep := NewRSAOaep(sha256.New())

	cipherText, err := oaep.Encrypt(&privateKey.PublicKey, []byte(message), label)
	if err != nil {
		t.Fatal(err)
	}

	decriptedMessage, err := oaep.Dencrypt(privateKey, cipherText, label)
	if err != nil {
		t.Fatal(err)
	}

	if string(decriptedMessage) != message {
		t.Fatal("Should be expected encoded message")
	}
}
