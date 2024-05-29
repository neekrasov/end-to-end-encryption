package main

import (
	"fmt"

	"github.com/neekrasov/end-to-end-encryption/internal/client"
)

func main() {
	if err := client.Run(); err != nil {
		fmt.Println(err)
	}
}
