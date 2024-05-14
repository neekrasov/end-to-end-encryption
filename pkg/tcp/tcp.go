package tcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/neekrasov/end-to-end-encryption/pkg/rsa"
)

// ----- Message Types -----------

type MessageType string

const (
	Connect      MessageType = "connect"
	Text         MessageType = "text"
	KeysExchange MessageType = "exhangekeys"
)

// ----- Messages ------------

type (
	Message struct {
		Type    MessageType `json:"type"`
		Payload []byte      `json:"payload"`
	}

	InitialMessage struct {
		Room      int            `json:"room"`
		PublicKey *rsa.PublicKey `json:"publicKey"`
	}

	TextMessage struct {
		Room int    `json:"room"`
		Text string `json:"text"`
	}

	KeyExchangeMessage struct {
		PublicKey *rsa.PublicKey `json:"publicKey"`
	}
)

func MakeMessage(msgType MessageType, msg any) (*Message, error) {
	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return &Message{Type: msgType, Payload: payload}, nil
}

func Read(r *bufio.Reader, v *[]byte) error {
	lengthBytes, err := r.ReadBytes('\n')
	if err != nil {
		return err
	}
	lengthBytes = bytes.TrimSpace(lengthBytes)

	length, err := strconv.Atoi(string(lengthBytes))
	if err != nil {
		return err
	}

	msgBytes := make([]byte, length)
	if _, err = r.Read(msgBytes); err != nil {
		return err
	}

	*v = msgBytes

	return nil
}

func Send(conn net.Conn, data []byte) error {
	if _, err := fmt.Fprintln(conn, len(data)); err != nil {
		return err
	}

	if _, err := conn.Write(data); err != nil {
		return err
	}

	return nil
}
