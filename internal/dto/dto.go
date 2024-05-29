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
	GetPubKey    MessageType = "pubkey"
	GetCert      MessageType = "cert"
)

// ----- Messages ------------

type (
	Certificate struct {
		Signature *big.Int `json:"signature"`
		Domain    string   `json:"domain"`
		ExpiresIn string   `json:"expiresIn"`
	}
	Message struct {
		Type    MessageType `json:"type"`
		Payload []byte      `json:"payload"`
	}

	InitialMsg struct {
		Room      int            `json:"room"`
		PublicKey *rsa.PublicKey `json:"publicKey"`
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

	GetCertMsg struct {
		Domain string `json:"domain"`
	}
)

func Make(msgType MessageType, msg any) ([]byte, error) {
	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	msgBytes, err := json.Marshal(Message{Type: msgType, Payload: payload})
	if err != nil {
		return nil, err
	}

	return msgBytes, nil
}
