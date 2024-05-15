package dto

import (
	"encoding/json"
	"math/big"

	"github.com/neekrasov/end-to-end-encryption/pkg/rsa"
)

// ----- Message Types -----------

type MessageType string

const (
	Connect      MessageType = "connect"
	CipherData   MessageType = "cipherdata"
	KeysExchange MessageType = "exhangekeys"
)

// ----- Messages ------------

type (
	Message struct {
		Type    MessageType `json:"type"`
		Payload []byte      `json:"payload"`
	}

	InitialMsg struct {
		Room      int            `json:"room"`
		PublicKey *rsa.PublicKey `json:"publicKey"`
	}

	TextMessage struct {
		Room int    `json:"room"`
		Text string `json:"text"`
	}

	CypherMsg struct {
		RoomID                 int      `json:"room"`
		SignedHashAESKeyAndMsg *big.Int `json:"signedHashAESKeyAndMsg"`
		EncryptedAESKey        *big.Int `json:"encryptedAESKey"`
		EncryptesMsg           []byte   `json:"encryptesMsg"`
	}

	KeyExchangeMsg struct {
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
