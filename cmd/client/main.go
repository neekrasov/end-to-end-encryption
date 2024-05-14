package main

import (
	"fmt"

	"github.com/neekrasov/end-to-end-encryption/internal/client"
)

func main() {
	if err := client.Client(); err != nil {
		fmt.Println(err)
	}
}
