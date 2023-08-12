package identity

import "crypto"

type HashType uint

const (
	HASH_TYPE_SM3      HashType = 20
	HASH_TYPE_SHA256   HashType = HashType(crypto.SHA256)
	HASH_TYPE_SHA3_256 HashType = HashType(crypto.SHA3_256)
)

// constant UID for SM2-SM3
const CRYPTO_DEFAULT_UID = "1234567812345678"

// 秘钥类型
type KeyType int

const (
	// 对称秘钥
	AES KeyType = iota
	SM4
	// 非对称秘钥
	RSA512
	RSA1024
	RSA2048
	RSA3072
	SM2
	ECC_Secp256k1
	ECC_NISTP256
	ECC_NISTP384
	ECC_NISTP521
	ECC_Ed25519
)

var ID_CA_PATH string = `ca`
var ID_ItermCA_PATH string = `inter_ca`
var ID_SIGN_PATH string = `id`
var ID_KEY_PATH string = `key`
