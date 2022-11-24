# micaes

 AES加密解密算法包

# 用法

## 创建加密解密结构

```go
//创建结构体,第一个参数是密钥，16、24或者32个字符,需要保密
//第二个参数是是初始向量,一般16个字符
//第三个参数为bool型可选参数,用于确定是否对长度不符合要求的key和iv自动补全。
//   其为false时,如果key或者iv的长度不符合要求，会返回错误信息
//   其为true时,如果key或者iv的长度不符合要求,会自动补全
aes, err := NewMicaes("abcdefebdkhgidhe", "1234567890abcdef",false) 
if err != nil {
  fmt.Pringtf("发生错误:%s", err.Error())
}
```

## 加密

```go
//加密,输入参数是需要加密的明文
ciphertext:=aes.Encrypt("其实，奥观海、川建国、拜振华都是我们的特工")
fmt.Pringtf("密文是:%s", ciphertext)
//密文是:WvpDEr51eH5PagDCI4l2FGVOni4a1oVuyREYogfU/8QqkZYcmDAxQ1o7tMyOz9g0hZEbpNuoogZYoJbzo+8UYQ==
```

## 解密

```go
//解密，输入的参数是待解密的密文
plaintext,err:=aes.Decrypt("WvpDEr51eH5PagDCI4l2FGVOni4a1oVuyREYogfU/8QqkZYcmDAxQ1o7tMyOz9g0hZEbpNuoogZYoJbzo+8UYQ==")
if err !=nil {
    fmt.Pringtf("解密错误:%s",err.Error())
}
fmt.Pringtf("我的秘密是:%s", plaintext)
//我的秘密是:其实，奥观海、川建国、拜振华都是我们的特工
```

详细用法请参见`aes_test.go`中的用例。
