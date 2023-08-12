package identity

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type Option interface {
}

type SignOpts struct {
	Hash         HashType
	UID          string
	EncodingType string
}

// Encryption options
type EncOpts struct {
	EncodingType string
	BlockMode    string
	EnableMAC    bool
	Hash         HashType
	Label        []byte
	EnableASN1   bool
}

type Key interface {
	Bytes() ([]byte, error)
	Type() KeyType
	String() (string, error)

	//非对称
	Sign(digest []byte) ([]byte, error)
	SignWithOpts(data []byte, opts *SignOpts) ([]byte, error)
	PublicKey() Key
	ToStandardKey() Key
	Verify(data []byte, sig []byte) (bool, error)
	VerifyWithOpts(data []byte, sig []byte, opts *SignOpts) (bool, error)

	//对称
	Encrypt(plain []byte) ([]byte, error)
	EncryptWithOpts(plain []byte, opts *EncOpts) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptWithOpts(ciphertext []byte, opts *EncOpts) ([]byte, error)
}

type ECDSAPrivateKey struct {
	data []byte
	key  *ecdsa.PrivateKey
}

func (k *ECDSAPrivateKey) Bytes() ([]byte, error) {
	return nil, nil
}

func (k *ECDSAPrivateKey) Type() KeyType {
	return 1
}

func (k *ECDSAPrivateKey) String() (string, error) {
	return "", nil
}

func (k *ECDSAPrivateKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, k.key, digest)
	if err != nil {
		return nil, err
	}

	s, err = toLowS(&k.key.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return MarshalECDSASignature(r, s)
}

func (k *ECDSAPrivateKey) SignWithOpts(data []byte, opts *SignOpts) ([]byte, error) {
	return nil, nil
}

func (k *ECDSAPrivateKey) PublicKey() Key {
	return &ECDSAPublicKey{nil, &k.key.PublicKey}
}

func (k *ECDSAPrivateKey) ToStandardKey() Key {
	return nil
}

func (k *ECDSAPrivateKey) Verify(data []byte, sig []byte) (bool, error) {
	return false, fmt.Errorf("not support")
}

func (k *ECDSAPrivateKey) VerifyWithOpts(data []byte, sig []byte, opts *SignOpts) (bool, error) {
	return false, fmt.Errorf("not support")
}

func (k *ECDSAPrivateKey) Encrypt(plain []byte) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}

func (k *ECDSAPrivateKey) EncryptWithOpts(plain []byte, opts *EncOpts) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}

func (k *ECDSAPrivateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}

func (k *ECDSAPrivateKey) DecryptWithOpts(ciphertext []byte, opts *EncOpts) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}

type ECDSAPublicKey struct {
	data []byte
	key  *ecdsa.PublicKey
}

func (k *ECDSAPublicKey) Bytes() ([]byte, error) {
	return nil, nil
}

func (k *ECDSAPublicKey) Type() KeyType {
	return 1
}

func (k *ECDSAPublicKey) String() (string, error) {
	return "", nil
}

func (k *ECDSAPublicKey) Sign(digest []byte) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}

func (k *ECDSAPublicKey) SignWithOpts(data []byte, opts *SignOpts) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}

func (k *ECDSAPublicKey) PublicKey() Key {
	return k
}

func (k *ECDSAPublicKey) ToStandardKey() Key {
	return nil
}

func (k *ECDSAPublicKey) Verify(msg []byte, sig []byte) (bool, error) {
	hash := sha256.New()
	hash.Write(msg)
	digest := hash.Sum(nil)

	r, s, err := UnmarshalECDSASignature(sig)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := isLowS(k.key, s)
	if err != nil {
		return false, err
	}
	if !lowS {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, big.NewInt(0).Set(curveHalfOrders[k.key.Curve]))
	}

	return ecdsa.Verify(k.key, digest, r, s), nil
}
func (k *ECDSAPublicKey) VerifyWithOpts(data []byte, sig []byte, opts *SignOpts) (bool, error) {
	return true, nil
}
func (k *ECDSAPublicKey) Encrypt(plain []byte) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}
func (k *ECDSAPublicKey) EncryptWithOpts(plain []byte, opts *EncOpts) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}
func (k *ECDSAPublicKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}
func (k *ECDSAPublicKey) DecryptWithOpts(ciphertext []byte, opts *EncOpts) ([]byte, error) {
	return nil, fmt.Errorf("not support")
}
