package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
)

func main() {
	var c conf
	c.getConf()
	pwdwithsalt := AesEncrypt(c.Password, c.EncryptionValueStr)
	fmt.Printf("加密后为：%s", pwdwithsalt)
}

type conf struct {
	Password           string `yaml:"password"`
	EncryptionValueStr string `yaml:"encryptionValueStr"`
}

func (c *conf) getConf() *conf {

	fmt.Printf("开始读取配置~\n")
	yamlFile, err := ioutil.ReadFile("./conf.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}

	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return c
}

func AesEncrypt(orig string, key string) string {
	// 转成字节数组
	origData := []byte(orig)
	k := []byte(key)

	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补全码
	origData = PKCS7Padding(origData, blockSize)
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	// 创建数组
	cryted := make([]byte, len(origData))
	// 加密
	blockMode.CryptBlocks(cryted, origData)

	return base64.StdEncoding.EncodeToString(cryted)

}

// 补码
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
