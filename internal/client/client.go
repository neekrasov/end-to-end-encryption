package client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/neekrasov/end-to-end-encryption/internal/dto"
	"github.com/neekrasov/end-to-end-encryption/pkg/aes"
	"github.com/neekrasov/end-to-end-encryption/pkg/rsa"
	"github.com/neekrasov/end-to-end-encryption/pkg/tcp"
	"github.com/pkg/errors"
)

func Run() error {
	fmt.Print("Enter room identifier: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return errors.Wrap(err, "failed to read message")
	}

	roomID, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil {
		return errors.Wrap(err, "failed to cast roomID into int")
	}

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

	fmt.Println("Getting cert pub key...")
	certPubKey, err := getCertPubKey()
	if err != nil {
		return errors.Wrap(err, "failed to get cert pub key")
	}

	fmt.Println("Getting server cert...")
	serverCert, err := getServerCert(serverConn)
	if err != nil {
		return errors.Wrap(err, "failed to get server cert")
	}

	fmt.Println("Checking server cert...")
	if err := checkCert(serverCert, certPubKey); err != nil {
		return errors.Wrap(err, "check cert failed")
	}
	fmt.Println("Server certificate check is succesfully")

	fmt.Println("Make initial message")
	initialMsg, err := dto.Make(dto.Connect, &dto.InitialMsg{
		Room:      roomID,
		PublicKey: pubKey,
	})
	if err != nil {
		return errors.Wrap(err, "failed to make initial message")
	}

	fmt.Println("Send initial message to server")
	if err = tcp.Send(serverConn, initialMsg); err != nil {
		return errors.Wrap(err, "failed to send initial message")
	}

	reader := bufio.NewReader(serverConn)
	updateRecipientPubKey := make(chan *rsa.PublicKey)
	go func(r *bufio.Reader, updateRecipientPubKey chan *rsa.PublicKey, privKey *rsa.PrivateKey) {
		if err := readRecipient(r, updateRecipientPubKey, privKey); err != nil {
			fmt.Printf("\nfailed to read recipient: %s", err.Error())
		}
	}(reader, updateRecipientPubKey, privKey)

	go func(roomID int, updateRecipientPubKey chan *rsa.PublicKey, privKey *rsa.PrivateKey, serverConn net.Conn) {
		if err := readStdIn(roomID, updateRecipientPubKey, privKey, serverConn); err != nil {
			fmt.Printf("\nfailed to read stdin: %s", err.Error())
		}
	}(roomID, updateRecipientPubKey, privKey, serverConn)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	fmt.Println("\nShutting down ...")

	return nil
}

func readStdIn(roomID int, updateRecipientPubKey chan *rsa.PublicKey, privKey *rsa.PrivateKey, serverConn net.Conn) error {
	var recipientPubKey *rsa.PublicKey

	if recipientPubKey == nil {
		fmt.Println("Wait recipient public key...")
		recipientPubKey = <-updateRecipientPubKey
	}

	go func() {
		for val := range updateRecipientPubKey {
			recipientPubKey = val
		}
	}()

	stdinReader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter message: ")
		input, err := stdinReader.ReadString('\n')
		if err != nil {
			return errors.Wrap(err, "failed to read message")
		}

		cypherMsg, err := encryptMsg(strings.TrimSpace(input), roomID, recipientPubKey, privKey)
		if err != nil {
			return errors.Wrap(err, "Failed to make cypher message")
		}

		msg, err := dto.Make(dto.CipherData, cypherMsg)
		if err != nil {
			return errors.Wrap(err, "failed to make text message")
		}

		fmt.Println("Send message...")
		if err := tcp.Send(serverConn, msg); err != nil {
			return errors.Wrap(err, "failed to send message to server")
		}
	}
}

func readRecipient(r *bufio.Reader, updateRecipientPubKey chan *rsa.PublicKey, privKey *rsa.PrivateKey) error {
	var recipientPubKey *rsa.PublicKey
	for {
		var msgBytes []byte
		if err := tcp.Read(r, &msgBytes); err != nil {
			return errors.Wrap(err, "failed to read server message")
		}

		var msg dto.Message
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			return errors.Wrap(err, "failed to unmarshall message")
		}

		switch msg.Type {
		case dto.KeysExchange:
			var kem dto.KeyExchangeMsg
			if err := json.Unmarshal(msg.Payload, &kem); err != nil {
				return errors.Wrap(err, "failed to unmarshall key exhange message bytes")
			}
			updateRecipientPubKey <- kem.PublicKey
			recipientPubKey = kem.PublicKey
		case dto.CipherData:
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

func getCertPubKey() (*rsa.PublicKey, error) {
	certConn, err := net.Dial("tcp", "localhost:8081")
	if err != nil {
		return nil, errors.Wrap(err, "error connect cert server")
	}
	defer certConn.Close()

	getPubKeyMsg, err := dto.Make(dto.GetPubKey, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to make get pub key cert server msg")
	}

	if err = tcp.Send(certConn, getPubKeyMsg); err != nil {
		return nil, errors.Wrap(err, "failed to send get pub key msg to cert server")
	}

	var pubKeyBytes []byte
	if err = tcp.Read(bufio.NewReader(certConn), &pubKeyBytes); err != nil {
		return nil, errors.Wrap(err, "failed to read pub key from cert server")
	}

	var pubKey rsa.PublicKey
	if err = json.Unmarshal(pubKeyBytes, &pubKey); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall cert server pub key")
	}

	return &pubKey, nil
}

func getServerCert(serverConn net.Conn) (*dto.Certificate, error) {
	getCertMsg, err := dto.Make(dto.GetCert, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to make get server cert msg")
	}

	if err = tcp.Send(serverConn, getCertMsg); err != nil {
		return nil, errors.Wrap(err, "failed to send domain to certification server")
	}

	var certBytes []byte
	if err = tcp.Read(bufio.NewReader(serverConn), &certBytes); err != nil {
		return nil, errors.Wrap(err, "failed to read cert from certification server")
	}

	var cert dto.Certificate
	if err = json.Unmarshal(certBytes, &cert); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall cert pubkey")
	}

	return &cert, nil
}

func checkCert(cert *dto.Certificate, certServerPubKey *rsa.PublicKey) error {
	hash, err := rsa.HashSHA256(cert.Domain + cert.ExpiresIn)
	if err != nil {
		return errors.Wrap(err, "error hashing domain expiresIn certificate sum")
	}

	if !rsa.Verify(cert.Signature, hash, certServerPubKey) {
		return errors.New("certificate is fake")
	}

	certTime, err := time.Parse("2006-01-02 15:04:05", cert.ExpiresIn)
	if err != nil {
		return errors.Wrap(err, "failed to parse cert expiresIs time")
	}

	if certTime.Before(time.Now().UTC()) {
		return errors.New("the certificate has expired")
	}

	return nil
}
