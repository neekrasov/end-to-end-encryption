package main

import (
	"fmt"

	center "github.com/neekrasov/end-to-end-encryption/internal/cert_center"
)

func main() {
	if err := center.Run(); err != nil {
		fmt.Println(err)
	}
}
