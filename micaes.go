package micaes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
)

type Micaes struct {
	key        []byte       //密钥，长度必须为16,24或32
	iv         []byte       //初始向量 Initialization Vector,长度必须等于key
	block      cipher.Block //
	blocksize  int
	Plaintext  string //平文
	Ciphertext string //密文
}

//创建一个加密解密结构
func NewMicaes(key, iv string, autopadding ...bool) (*Micaes, error) {
	ma := new(Micaes)
	err := ma.init(key, iv, autopadding...)
	return ma, err
}

//初始化
func (ma *Micaes) init(keys, ivs string, autopadding ...bool) error {
	autop := false
	if len(autopadding) > 0 {
		{
			autop = autopadding[0]
		}
	}
	//key不可为空
	err := ma.keyPadding([]byte(keys), autop)
	if err != nil {
		return err
	}

	//创建加密实例
	block, err := aes.NewCipher(ma.key)
	if err != nil {
		return err
	}
	ma.block = block
	ma.blocksize = ma.block.BlockSize()

	//如果iv为空,使iv=key
	err = ma.ivPadding([]byte(ivs), autop)
	if err != nil {
		return err
	}
	//fmt.Printf("密钥:%s,Iv:%s,BlockSize:%d ===============\n", ma.key, ma.iv, ma.blocksize)
	return nil
}

//是否自动补充密钥
func (ma *Micaes) keyPadding(key []byte, autopadding bool) error {
	keylen := len(key)
	if keylen == 0 {
		return fmt.Errorf("key can not be empty")
	}
	if keylen > 8 && keylen <= 32 && keylen%8 == 0 { //长度符合规定：16,24或32
		ma.key = key
		return nil
	} else {
		if !autopadding { //非自动补全
			return fmt.Errorf("invalid key length %d", keylen)
		}
		paddinglen := 0
		if keylen < 16 {
			paddinglen = 16 - keylen
		} else if keylen < 24 {
			paddinglen = 24 - keylen
		} else if keylen < 32 {
			paddinglen = 32 - keylen
		} else {
			ma.key = key[:32]
			return nil
		}

		//补全
		for i := 0; i < paddinglen; i++ {
			j := i
			if j >= keylen {
				j = i % keylen
			}
			key = append(key, key[j])
		}
		ma.key = key
		return nil
	}
}

//是否自动补充初始向量
func (ma *Micaes) ivPadding(iv []byte, autopadding bool) error {
	ivlen := len(iv)
	if ivlen == 0 {
		ma.iv = ma.key[:ma.blocksize]
		return nil
	}
	if ivlen > ma.blocksize {
		ma.iv = iv[:ma.blocksize]
		return nil
	} else {
		if !autopadding {
			return fmt.Errorf("invalid iv length %d", ivlen)
		}
		paddinglen := ma.blocksize - ivlen

		for i := 0; i < paddinglen; i++ {
			j := i
			if j >= ivlen {
				j = i % ivlen
			}
			iv = append(iv, iv[j])
		}
		ma.iv = iv
		return nil
	}
}

//pkcs7Padding 填充
func (ma *Micaes) pkcs7Padding(data []byte) []byte {
	//判断缺少几位长度。最少1，最多 blockSize
	padding := ma.blocksize - len(data)%ma.blocksize
	//补足位数。把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

//pkcs7UnPadding 填充的反向操作
func (ma *Micaes) pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

//AesEncrypt 加密
func (ma *Micaes) AesEncrypt(plaintext string) error {
	ma.Plaintext = plaintext
	//填充
	encryptBytes := ma.pkcs7Padding([]byte(plaintext))
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(ma.block, ma.iv)
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	//Base64加密
	ma.Ciphertext = base64.StdEncoding.EncodeToString(crypted)
	return nil
}

//AesDecrypt 解密
func (ma *Micaes) AesDecrypt(ciphertext string) error {
	dataByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return err
	}

	ma.Ciphertext = ciphertext
	//使用cbc
	blockMode := cipher.NewCBCDecrypter(ma.block, ma.iv)
	//初始化解密数据接收切片
	crypted := make([]byte, len(dataByte))
	//执行解密
	blockMode.CryptBlocks(crypted, dataByte)
	//去除填充
	crypted, err = ma.pkcs7UnPadding(crypted)
	if err != nil {
		return err
	}
	ma.Plaintext = string(crypted)
	return nil
}
