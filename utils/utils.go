package utils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// utils
func HexaNumberToInteger(hexaString string) string {
	numberStr := strings.Replace(hexaString, "0x", "", -1)
	numberStr = strings.Replace(numberStr, "0X", "", -1)
	return numberStr
}

func Convertip(hexip string) (string, error) {
	if len(hexip) < 10 {
		return "", errors.New("minimum size 10")
	}
	hex, err := hex.DecodeString(HexaNumberToInteger(hexip))
	if err != nil {
		return "", err
	}
	ip := fmt.Sprintf("%d.%d.%d.%d", int(hex[3]), int(hex[2]), int(hex[1]), int(hex[0]))
	return ip, nil
}

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func Zfill(s string, pad string, overall int) string {
	l := overall - len(s)
	return strings.Repeat(pad, l) + s
}
