package googleotp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"time"
)

const (
	interval = 30
)

// integer to byte array
func itob(integer int) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	}
	return byteArr
}

func GenerateKey() (key string) {
	secret := make([]byte, 15)
	rand.Read(secret)
	key = base32.StdEncoding.EncodeToString([]byte(secret))
	return
}

func Validate(key string, codeToCheck int) (valid bool, err error) {
	msg := int(time.Now().Unix() / interval)
	keyBytes, err := base32.StdEncoding.DecodeString(key)
	if err != nil {
		fmt.Println("TOTP code check error:", err)
	}
	hasher := hmac.New(sha1.New, keyBytes)
	hasher.Write(itob(msg))
	hmacHash := hasher.Sum(nil)
	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)
	code = code % int(1e6)
	if codeToCheck == code {
		valid = true
	}
	return
}
