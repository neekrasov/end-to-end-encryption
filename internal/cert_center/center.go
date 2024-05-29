package certcenter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/neekrasov/end-to-end-encryption/internal/dto"
	"github.com/neekrasov/end-to-end-encryption/pkg/rsa"
	"github.com/neekrasov/end-to-end-encryption/pkg/tcp"
	"github.com/pkg/errors"
)

func Run() error {
	fmt.Println("Generate keys...")
	pubKey, privKey, err := rsa.GenerateKeys(512)
	if err != nil {
		return errors.Wrap(err, "failed to generate keys")
	}

	ln, err := net.Listen("tcp", ":8081")
	if err != nil {
		return fmt.Errorf("error starting certification server: %w", err)
	}
	log.Println("Certification server was started")

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		go handleConnection(clientConn, pubKey, privKey)
	}
}

func handleConnection(
	conn net.Conn,
	pubKey *rsa.PublicKey,
	privKey *rsa.PrivateKey,
) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	var msgBytes []byte
	if err := tcp.Read(reader, &msgBytes); err != nil {
		log.Printf("Failed to read client message: %s", err.Error())
		return
	}

	var msg dto.Message
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		log.Printf("Failed to unmarshall message: %s", err.Error())
		return
	}

	switch msg.Type {
	case dto.GetPubKey:
		msgBytes, err := json.Marshal(pubKey)
		if err != nil {
			log.Printf("failed to marshal get pub key response: %s", err.Error())
			return
		}

		if err = tcp.Send(conn, msgBytes); err != nil {
			log.Printf("failed to send get pub key response: %s", err.Error())
			return
		}
	case dto.GetCert:
		var getCertMsg dto.GetCertMsg
		if err := json.Unmarshal(msg.Payload, &getCertMsg); err != nil {
			log.Printf("failed to unmarshall get cert msg: %s", err.Error())
			return
		}

		expiresIn := time.Now().Add(time.Minute).UTC().Format("2006-01-02 15:04:05")
		hash, err := rsa.HashSHA256(getCertMsg.Domain + expiresIn)
		if err != nil {
			log.Printf("error hashing domain expiresIn certificate sum: %s", err.Error())
			return
		}

		certBytes, err := json.Marshal(dto.Certificate{
			Signature: rsa.Sign(hash, privKey),
			Domain:    getCertMsg.Domain,
			ExpiresIn: expiresIn,
		})
		if err != nil {
			log.Printf("failed to marshall cert: %s", err.Error())
			return
		}

		if err = tcp.Send(conn, certBytes); err != nil {
			log.Printf("failed to send cert response: %s", err.Error())
			return
		}
	}
}
