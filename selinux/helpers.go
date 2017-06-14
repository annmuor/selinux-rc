package selinux

import (
	"bytes"
	"fmt"
)

func bb2string(v [][]byte) string {
	if v[0] == nil {
		return ""
	}
	return b2string(v[0])
}

func b2string(v []byte) string {
	if v == nil {
		return ""
	}
	return string(v[:bytes.IndexByte(v, 0)])
}

func printarray(array []string) {
	for i,v := range array {
		fmt.Printf("%d:%s ", i, v)
	}
	println()
}