package micaes

import "testing"

func TestInit(t *testing.T) {
	tests := []struct {
		key    string
		iv     string
		aeskey string
		aesiv  string
	}{
		{"1234567890", "", "1234567890123456", "1234567890123456"},                                                                        //<16
		{"1234567890abcdef", "", "1234567890abcdef", "1234567890abcdef"},                                                                  //==16
		{"1234567890abcdef1", "", "1234567890abcdef11234567", "1234567890abcdef"},                                                         //<24
		{"1234567890abcdef12345678", "", "1234567890abcdef12345678", "1234567890abcdef"},                                                  //==24
		{"1234567890abcdef123456789", "", "1234567890abcdef1234567891234567", "1234567890abcdef"},                                         //<32
		{"1234567890abcdef1234567890abcdef", "", "1234567890abcdef1234567890abcdef", "1234567890abcdef"},                                  //==32
		{"1234567890abcdef1234567890abcdefd", "", "1234567890abcdef1234567890abcdef", "1234567890abcdef"},                                 //>32
		{"1234567890abcdef1234567890abcdef", "0000000000000000", "1234567890abcdef1234567890abcdef", "0000000000000000"},                  //len iv < len key
		{"1234567890abcdef1234567890abcdef", "00000000000000001234567890abcdefx", "1234567890abcdef1234567890abcdef", "0000000000000000"}, //len iv >len key
	}

	for i, tt := range tests {
		i += 1
		aes, err := NewMicaes(tt.key, tt.iv, true)
		if err != nil {
			t.Errorf("第%d用例,创建结构错误:%s", i, err.Error())
		} else {
			if string(aes.key) != tt.aeskey {
				t.Errorf("第%d用例:获得的key=%s,期望的key=%s", i, string(aes.key), tt.aeskey)
			}
			if string(aes.iv) != tt.aesiv {
				t.Errorf("第%d用例:获得的Iv=%s,期望的Iv=%s", i, string(aes.iv), tt.aesiv)
			}
		}
	}
}

func TestEncodeAes(t *testing.T) {
	tests := []struct {
		key  string
		iv   string
		data string
	}{
		{"1234567890", "1234567890", "注意在加密时，平文中的微小改变会导致其后的全部密文块发生改变，而在解密时，从两个邻接的密文块中即可得到一个平文块。因此，解密过程可以被并行化，而解密时，密文中一位的改变只会导致其对应的平文块完全改变和下一个平文块中对应位发生改变，不会影响到其它平文的内容ddddddd"},
		{"1234567890abcdef", "1234567890", "1234567890123456"},
		{"1234567890abcdefg", "1234567890", "1234567890123456"},
	}
	for i, tt := range tests {
		t.Logf("=================%d=================", i)
		eaes, err := NewMicaes(tt.key, tt.iv, true)
		if err != nil {
			t.Errorf("创建加密实例错误:%s", err.Error())
		} else {
			ciphertext := eaes.Encrypt(tt.data)
			daes, err := NewMicaes(tt.key, tt.iv, true)
			if err != nil {
				t.Errorf("创建解密实例错误:%s", err.Error())
			} else {
				plaintext, err := daes.Decrypt(ciphertext)
				if err != nil {
					t.Errorf("解密错误:%s", err.Error())
				} else {
					t.Logf("原文:%s,len=%d", tt.data, len(tt.data))
					t.Logf("密文:%s,len=%d", ciphertext, len(ciphertext))
					t.Logf("解密文:%s,len=%d", plaintext, len(plaintext))
				}
			}
		}

	}
}

func TestEncode(t *testing.T) {
	aes, err := NewMicaes("abcdefebdkhgidhe", "1234567890abcdef") //创建结构
	if err != nil {
		t.Errorf("发生错误:%s", err.Error())
	} else {
		ciphertext := aes.Encrypt("其实，奥观海、川建国、拜振华都是我们的特工")
		t.Logf("密文是:%s", ciphertext)
	}
}

func TestDecode(t *testing.T) {
	aes, err := NewMicaes("abcdefebdkhgidhe", "1234567890abcdef") //创建结构
	if err != nil {
		t.Errorf("发生错误:%s", err.Error())
	} else {
		plaintext, _ := aes.Decrypt("WvpDEr51eH5PagDCI4l2FGVOni4a1oVuyREYogfU/8QqkZYcmDAxQ1o7tMyOz9g0hZEbpNuoogZYoJbzo+8UYQ==")
		t.Logf("我的秘密是:%s", plaintext)
	}
}
