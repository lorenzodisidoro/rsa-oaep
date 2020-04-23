# RSA Optimal Asymmetric Encryption Padding

This package implements "crypto/rsa" lib wrapper which encrypt and decrypt messages

```golang
type OAEP struct {
   hash   hash.Hash
   random io.Reader
}
```

- `hash` hash function
- `random` random parameter is used as a source of entropy to ensure that encrypting

## Install package

```sh
go get github.com/lorenzodisidoro/rsa-oaep
```

## Methods

### OAEP instance
```golang
oaep := NewRSAOaep(sha256.New())
```

### Encrypt and decrypt message
The following code is used to encrypt and decrypt message

```golang
// you will import "crypto/rsa" and "crypto/rand"
privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
if err != nil {
    t.Fatal(err)
}
    
message := []byte("Love bitcoin!")
label   := []byte("bitcoin")
oaep    := NewRSAOaep(sha256.New())

cipherText, err := oaep.Encrypt(&privateKey.PublicKey, message, label)
if err != nil {
    t.Fatal(err)
}

decriptedMessage, err := oaep.Dencrypt(privateKey, cipherText, label)
if err != nil {
    t.Fatal(err)
}

fmt.Printf(string(decriptedMessage))
```
