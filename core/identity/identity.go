package identity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"npcc/common/config"
	"path/filepath"
)

type Identity struct {
	ID      string
	Name    string
	pubKey  Key
	privKey Key
}

func (id *Identity) InitID(cf *config.LocalConfig) error {
	//初始化ca、中间ca
	pemBytes, err := getPemMaterialFromDir(filepath.Join(cf.Path, ID_CA_PATH))
	if err != nil {
		return err
	}
	opts := &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	for _, v := range pemBytes {
		pemCert, _ := pem.Decode(v)
		cert, err := x509.ParseCertificate(pemCert.Bytes)
		if err != nil {
			return err
		}
		opts.Roots.AddCert(cert)
	}
	pemBytes, err = getPemMaterialFromDir(filepath.Join(cf.Path, ID_ItermCA_PATH))
	if err != nil {
		return err
	}
	for _, v := range pemBytes {
		pemCert, _ := pem.Decode(v)
		cert, err := x509.ParseCertificate(pemCert.Bytes)
		if err != nil {
			return err
		}
		opts.Intermediates.AddCert(cert)
	}

	//初始化身份签名证书
	pemBytes, err = getPemMaterialFromDir(filepath.Join(cf.Path, ID_SIGN_PATH))
	if err != nil {
		return err
	}
	pemBlock, _ := pem.Decode(pemBytes[0])
	signCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}
	pk, ok := signCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not ecdsa public key")
	}
	id.pubKey = &ECDSAPublicKey{data: pemBytes[0], key: pk}

	hash := sha256.New()
	_, err = hash.Write(signCert.Raw)
	if err != nil {
		return fmt.Errorf("failed hashing raw cert to compute id of Identity: %s", err)
	}
	id.ID = hex.EncodeToString(hash.Sum(nil))

	//解析私钥
	pemBytes, err = getPemMaterialFromDir(filepath.Join(cf.Path, ID_KEY_PATH))
	if err != nil {
		return err
	}
	pemBlock, _ = pem.Decode(pemBytes[0])
	sk, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err == nil {
		id.privKey = &ECDSAPrivateKey{data: pemBytes[0], key: sk}
		return nil
	}
	k, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return err
	}

	sk, ok = k.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("no ecdsa private key")
	}
	id.privKey = &ECDSAPrivateKey{data: pemBytes[0], key: sk}

	return nil
}

func (id *Identity) Sign(data []byte, opts *SignOpts) ([]byte, error) {
	return id.privKey.Sign(data)
}

func (id *Identity) Verify(data []byte, sig []byte, opts *SignOpts) (bool, error) {
	return id.pubKey.Verify(data, sig)
}
