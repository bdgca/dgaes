package micaes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

type Micaes struct {
	key        []byte       //密钥，长度必须为16,24或32
	iv         []byte       //初始向量 Initialization Vector,长度必须等于key
	block      cipher.Block //
	blocksize  int          //加密块的长度
	Plaintext  string       //平文
	Ciphertext string       //密文
}

//创建一个加密解密结构
//  输入参数:
//    key string:密钥,长度应为16、24或者32个字符
//    iv string:初始向量,可以为空或者16个字符
//    autopadding bool:可选参数,是否对长度不符合要求的key和iv自动补全。
//        false时,如果key或者iv的长度不符合要求，会返回错误信息
//        true时,如果key或者iv的长度不符合要求,会自动补全
//  输出参数:
//    *Micaes:创建的加密解密结构体
//    error:错误信息
//  说明:本加密解密算法使用AES CBC算法
//  时间:2022年11月24日
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
	return nil
}

//是否自动补充密钥
func (ma *Micaes) keyPadding(key []byte, autopadding bool) error {
	keylen := len(key)
	if keylen == 0 { //key 不可为空
		return fmt.Errorf("key can not be empty")
	}
	if keylen > 8 && keylen <= 32 && keylen%8 == 0 { //长度符合规定：16,24或32
		ma.key = key
		return nil
	} else {
		if !autopadding { //未设定自动补全,返回密钥长度错误
			return fmt.Errorf("invalid key length %d", keylen)
		}
		paddinglen := 0 //需要补全的长度
		//根据当前密钥的长度计算需要补全的长度
		if keylen < 16 {
			paddinglen = 16 - keylen
		} else if keylen < 24 {
			paddinglen = 24 - keylen
		} else if keylen < 32 {
			paddinglen = 32 - keylen
		} else {
			ma.key = key[:32] //如果设定的密钥长度大于32个字符,则取前32个字符
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
	//如果初始向量为空,则取密钥中的字符为初始向量
	if ivlen == 0 {
		ma.iv = ma.key[:ma.blocksize]
		return nil
	}
	//如果设定的初始向量长度大于加密块的长度
	if ivlen > ma.blocksize {
		ma.iv = iv[:ma.blocksize] //取前 blocksize个字符
		return nil
	} else {
		//未设定自动补全,返回错误信息
		if !autopadding {
			return fmt.Errorf("invalid iv length %d", ivlen)
		}
		//计算需要补全的长度
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
		return nil, fmt.Errorf("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

//Encrypt 加密
func (ma *Micaes) Encrypt(plaintext string) error {
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

//Decrypt 解密
func (ma *Micaes) Decrypt(ciphertext string) error {
	//Base64 解密
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
