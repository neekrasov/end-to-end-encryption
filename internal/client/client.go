package client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/neekrasov/end-to-end-encryption/internal/dto"
	"github.com/neekrasov/end-to-end-encryption/pkg/aes"
	"github.com/neekrasov/end-to-end-encryption/pkg/rsa"
	"github.com/neekrasov/end-to-end-encryption/pkg/tcp"
	"github.com/pkg/errors"
)

func Client() error {
	fmt.Println("Generate keys...")
	pubKey, privKey, err := rsa.GenerateKeys(512)
	if err != nil {
		return errors.Wrap(err, "failed to generate keys")
	}

	fmt.Println("Initialize connections...")
	serverConn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return errors.Wrap(err, "failed to initialize registrar connection")
	}
	defer serverConn.Close()

	roomID := 123
	reader := bufio.NewReader(serverConn)
	recipientPubKey, err := connect(roomID, pubKey, reader, serverConn)
	if err != nil {
		return errors.Wrap(err, "connection to server failed")
	}

	go func(r *bufio.Reader, recipientPubKey *rsa.PublicKey, privKey *rsa.PrivateKey) {
		if err := readRecipient(r, recipientPubKey, privKey); err != nil {
			fmt.Printf("\nfailed to read recipient: %s", err.Error())
		}
	}(reader, recipientPubKey, privKey)

	go func(roomID int, recipientPubKey *rsa.PublicKey, privKey *rsa.PrivateKey, serverConn net.Conn) {
		if err := readStdIn(roomID, recipientPubKey, privKey, serverConn); err != nil {
			fmt.Printf("\nfailed to read stdin: %s", err.Error())
		}
	}(roomID, recipientPubKey, privKey, serverConn)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	fmt.Println("\nShutting down ...")
	if err := serverConn.Close(); err != nil {
		return errors.Wrap(err, "error closing server connection")
	}

	return nil
}

func connect(
	roomID int, pubKey *rsa.PublicKey,
	r *bufio.Reader, serverConn net.Conn,
) (*rsa.PublicKey, error) {
	fmt.Println("Make initial message")
	initialMsg, err := dto.MakeMessage(dto.Connect, &dto.InitialMsg{
		Room:      roomID,
		PublicKey: pubKey,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to make initial message")
	}

	initialMsgBytes, err := json.Marshal(initialMsg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal initial message")
	}

	fmt.Println("Send initial message to server")
	if err = tcp.Send(serverConn, initialMsgBytes); err != nil {
		return nil, errors.Wrap(err, "failed to send initial message")
	}

	fmt.Println("Wait public key repicient...")
	var keyExhangeMessageBytes []byte
	if err := tcp.Read(r, &keyExhangeMessageBytes); err != nil {
		return nil, errors.Wrap(err, "failed to read key exhange parent message")
	}

	var msg dto.Message
	if err := json.Unmarshal(keyExhangeMessageBytes, &msg); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall key exhange parent message bytes")
	}

	var kem dto.KeyExchangeMsg
	if err := json.Unmarshal(msg.Payload, &kem); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall key exhange message bytes")
	}
	fmt.Println("Recipient public key received")

	return kem.PublicKey, nil
}

func readStdIn(roomID int, recipientPubKey *rsa.PublicKey, privKey *rsa.PrivateKey, serverConn net.Conn) error {
	for {
		fmt.Print("Enter message: ")
		input, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return errors.Wrap(err, "failed to read message")
		}

		cypherMsg, err := encryptMsg(strings.TrimSpace(input), roomID, recipientPubKey, privKey)
		if err != nil {
			return errors.Wrap(err, "Failed to make cypher message")
		}

		msg, err := dto.MakeMessage(dto.CipherData, cypherMsg)
		if err != nil {
			return errors.Wrap(err, "failed to make text message")
		}

		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return errors.Wrap(err, "failed to marshal stdin message")
		}

		if err := tcp.Send(serverConn, msgBytes); err != nil {
			return errors.Wrap(err, "failed to send message to server")
		}
	}
}

func readRecipient(r *bufio.Reader, recipientPubKey *rsa.PublicKey, privKey *rsa.PrivateKey) error {
	for {
		var msgBytes []byte
		if err := tcp.Read(r, &msgBytes); err != nil {
			return errors.Wrap(err, "failed to read server message")
		}

		var msg dto.Message
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			return errors.Wrap(err, "failed to unmarshall message")
		}

		var cypherMsg dto.CypherMsg
		if err := json.Unmarshal(msg.Payload, &cypherMsg); err != nil {
			return errors.Wrap(err, "failed to unmarshall text message")
		}

		decryptedMsg, err := decryptMsg(&cypherMsg, recipientPubKey, privKey)
		if err != nil {
			return errors.Wrap(err, "failed to decrypt recipient msg")
		}

		fmt.Println("\nMessage from recipient: ", decryptedMsg)
		fmt.Print("\nEnter message: ")
		time.Sleep(1 * time.Second)
	}
}

func encryptMsg(msg string, roomID int, recipientPubKey *rsa.PublicKey, privKey *rsa.PrivateKey) (*dto.CypherMsg, error) {
	aesKey, err := rsa.GeneratePrime(512)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create aes key")
	}

	encryptedMsg, err := aes.Encrypt(msg, aesKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt message by aes key")
	}

	encryptedAesKey := rsa.Encrypt(aesKey, recipientPubKey)
	keyMsg := encryptedAesKey.Text(16) + string(encryptedMsg)
	hashedKeyMsg, err := rsa.HashSHA256(keyMsg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash key msg")
	}
	signedHashedKeyMsg := rsa.Sign(hashedKeyMsg, privKey)

	return &dto.CypherMsg{
		RoomID:                 roomID,
		SignedHashAESKeyAndMsg: signedHashedKeyMsg,
		EncryptedAESKey:        encryptedAesKey,
		EncryptesMsg:           encryptedMsg,
	}, nil
}

func decryptMsg(cypherMsg *dto.CypherMsg, recipientPubKey *rsa.PublicKey, privKey *rsa.PrivateKey) (string, error) {
	keyMsg := cypherMsg.EncryptedAESKey.Text(16) + string(cypherMsg.EncryptesMsg)
	hashedKeyMsg, err := rsa.HashSHA256(keyMsg)
	if err != nil {
		return "", errors.Wrap(err, "failed to hash key msg")
	}

	if !rsa.Verify(cypherMsg.SignedHashAESKeyAndMsg, hashedKeyMsg, recipientPubKey) {
		return "", errors.New("failed to verify recipient message")
	}

	aesKey := rsa.Decrypt(cypherMsg.EncryptedAESKey, privKey)
	msg, err := aes.Decrypt(cypherMsg.EncryptesMsg, aesKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt message by aes key")
	}

	return msg, nil
}
