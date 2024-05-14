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

	"github.com/neekrasov/end-to-end-encryption/pkg/rsa"
	"github.com/neekrasov/end-to-end-encryption/pkg/tcp"
	"github.com/pkg/errors"
)

func Client() error {
	fmt.Println("Generate keys...")
	pubKey, _, err := rsa.GenerateKeys(512)
	if err != nil {
		return errors.Wrap(err, "failed to generate keys")
	}

	fmt.Println("Generated pubkey", pubKey)

	fmt.Println("Initialize connections...")
	serverConn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return errors.Wrap(err, "failed to initialize registrar connection")
	}
	defer serverConn.Close()

	roomID := 123
	reader := bufio.NewReader(serverConn)
	var recipientPublicKey rsa.PublicKey
	if err := connect(roomID, pubKey, reader, &recipientPublicKey, serverConn); err != nil {
		return errors.Wrap(err, "connection to server failed")
	}

	go func(r *bufio.Reader) {
		if err := readRecipient(r); err != nil {
			fmt.Printf("\nfailed to read recipient: %s", err.Error())
		}
	}(reader)

	go func() {
		if err := readStdIn(roomID, serverConn); err != nil {
			fmt.Printf("\nfailed to read stdin: %s", err.Error())
		}
	}()

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
	r *bufio.Reader, recipientPubKey *rsa.PublicKey,
	serverConn net.Conn,
) error {
	fmt.Println("Make initial message")
	initialMsg, err := tcp.MakeMessage(tcp.Connect, &tcp.InitialMessage{
		Room:      roomID,
		PublicKey: pubKey,
	})
	if err != nil {
		return errors.Wrap(err, "failed to make initial message")
	}

	initialMsgBytes, err := json.Marshal(initialMsg)
	if err != nil {
		return errors.Wrap(err, "failed to marshal initial message")
	}

	fmt.Println("Send initial message to server")
	if err = tcp.Send(serverConn, initialMsgBytes); err != nil {
		return errors.Wrap(err, "failed to send initial message")
	}

	fmt.Println("Wait public key repicient...")
	var keyExhangeMessageBytes []byte
	if err := tcp.Read(r, &keyExhangeMessageBytes); err != nil {
		return errors.Wrap(err, "failed to read key exhange parent message")
	}

	fmt.Println(string(keyExhangeMessageBytes))

	var msg tcp.Message
	if err := json.Unmarshal(keyExhangeMessageBytes, &msg); err != nil {
		return errors.Wrap(err, "failed to unmarshall key exhange parent message bytes")
	}

	var kem tcp.KeyExchangeMessage
	if err := json.Unmarshal(msg.Payload, &kem); err != nil {
		return errors.Wrap(err, "failed to unmarshall key exhange message bytes")
	}

	fmt.Println(kem.PublicKey)

	recipientPubKey = kem.PublicKey

	return nil
}

func readStdIn(roomID int, serverConn net.Conn) error {
	for {
		fmt.Print("Enter message: ")
		input, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return errors.Wrap(err, "failed to read message")
		}
		stdinMsg := strings.TrimSpace(input)

		msg, err := tcp.MakeMessage(tcp.Text, &tcp.TextMessage{
			Room: roomID,
			Text: stdinMsg,
		})
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

func readRecipient(r *bufio.Reader) error {
	for {
		var msgBytes []byte
		if err := tcp.Read(r, &msgBytes); err != nil {
			return errors.Wrap(err, "failed to read server message")
		}

		var msg tcp.Message
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			return errors.Wrap(err, "failed to unmarshall message")
		}

		var textMsg tcp.TextMessage
		if err := json.Unmarshal(msg.Payload, &textMsg); err != nil {
			return errors.Wrap(err, "failed to unmarshall text message")
		}

		fmt.Println("Message from recipient: ", textMsg.Text)
		time.Sleep(1 * time.Second)
	}
}
