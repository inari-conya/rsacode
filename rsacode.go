package rsacode

import (
	"fmt"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"unicode/utf8"
	
	"github.com/inari-conya/l4g"
)

func RsaEncrypt(origData []byte, filename string) ([]byte, error) {
	pubkey, err := ioutil.ReadFile(filename)
	if err != nil {
		go l4g.Log("rsacode.log", "ERROR", "加密公钥读取失败:", err)
	}
	block, _ := pem.Decode(pubkey) //将密钥解析成公钥实例
	if block == nil {
		return nil, errors.New("key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData) //RSA算法加密
}

func RsaDecrypt(ciphertext []byte, filename string) ([]byte, error) {
	prikey, err := ioutil.ReadFile(filename)
	if err != nil {
		go l4g.Log("rsa.log", "ERROR", "解密私钥读取失败:", err)
	}
	block, _ := pem.Decode(prikey) //将密钥解析成私钥实例
	if block == nil {
		return nil, errors.New("key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext) //RSA算法解密
}

func RsaUTF8Decrypt(ciphertext []byte, filename string) (str string, err error) {
	prikey, err := ioutil.ReadFile(filename)
	if err != nil {
		go l4g.Log("rsa.log", "ERROR", "解密私钥读取失败:", err)
	}
	block, _ := pem.Decode(prikey) //将密钥解析成私钥实例
	if block == nil {
		return "", errors.New("key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return "", err
	}
	decode, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext) //RSA算法解密
	if err != nil {
		return "", err
	}
	str = ""
	for len(decode) > 0 {
		r, size := utf8.DecodeRune(decode)
		str += fmt.Sprintf("%c", r)
		decode = decode[size:]
	}
	return str, nil
}
