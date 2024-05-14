package main

import (
	"fmt"

	"github.com/neekrasov/end-to-end-encryption/internal/server"
	"github.com/neekrasov/end-to-end-encryption/pkg/room"
)

func main() {
	serv := server.New(room.New())
	if err := serv.Serve(); err != nil {
		fmt.Println(err)
	}
}
