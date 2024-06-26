package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/neekrasov/end-to-end-encryption/internal/dto"
	"github.com/neekrasov/end-to-end-encryption/pkg/room"
	"github.com/neekrasov/end-to-end-encryption/pkg/rsa"
	"github.com/neekrasov/end-to-end-encryption/pkg/tcp"
	"github.com/pkg/errors"
)

type Server struct {
	rooms  *room.RoomManager
	cert   *dto.Certificate
	domain string

	certMu sync.Mutex
}

func New(roomManager *room.RoomManager) *Server {
	return &Server{rooms: roomManager, domain: "somedomain"}
}

func (s *Server) Serve() error {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		return errors.Wrap(err, "error starting server")
	}
	log.Println("Server was started")

	s.cert, err = getCert(s.domain)
	if err != nil {
		return errors.Wrap(err, "error getting certificate")
	}
	log.Printf("Cert center certificate expires in: %v", s.cert.ExpiresIn)

	go s.updateCert()

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		go s.handleConnection(clientConn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	for {
		var msgBytes []byte
		if err := tcp.Read(reader, &msgBytes); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, net.ErrWriteToConnected) {
				addr := conn.RemoteAddr().String()
				s.rooms.RemoveClient(addr)
				log.Printf("Сlient %s disconnected", addr)
				return
			}
			log.Printf("Failed to read client message: %s", err.Error())
			return
		}

		var msg dto.Message
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			log.Printf("Failed to unmarshall message: %s", err.Error())
			return
		}

		switch msg.Type {
		case dto.GetCert:
			s.certMu.Lock()
			certBytes, err := json.Marshal(s.cert)
			if err != nil {
				log.Printf("Failed to marhall certificate: %s", err.Error())
				return
			}
			s.certMu.Unlock()

			if err := tcp.Send(conn, certBytes); err != nil {
				log.Printf("Failed to send certificate: %s", err.Error())
				return
			}
		case dto.Connect:
			client, roomID, position, err := s.handleInitial(conn, msg)
			if err != nil {
				log.Printf("failed to handle initial connect: %s", err.Error())
				return
			}

			log.Printf("Client %s joined to room %d on %s position", client.Addr, roomID, position)
		case dto.CipherData:
			if err := s.handleText(conn, msg); err != nil {
				log.Printf("failed to handle text: %s", err.Error())
				return
			}
		default:
			log.Println("unexpected message type: ", msg.Type)
			return
		}
	}
}

func (s *Server) handleInitial(conn net.Conn, msg dto.Message) (*room.Client, room.RoomID, room.Role, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("we was in panic: \n %v \n %v", string(debug.Stack()), fmt.Errorf("%v", r))
			return
		}
	}()

	var initialMsg dto.InitialMsg
	if err := json.Unmarshal(msg.Payload, &initialMsg); err != nil {
		return nil, 0, "", errors.Wrap(err, "failed to unmarshall initial message")
	}

	roomID := room.RoomID(initialMsg.Room)
	selectedRoom, err := s.rooms.GetRoom(roomID)
	if err != nil {
		s.rooms.Create(roomID)
		selectedRoom, err = s.rooms.GetRoom(roomID)
		if err != nil {
			return nil, 0, "", err
		}
	}

	if selectedRoom.First != nil && selectedRoom.Second != nil {
		return nil, 0, "", fmt.Errorf("the room %d is full", roomID)
	}

	client := room.Client{
		Addr:      conn.RemoteAddr().String(),
		Conn:      conn,
		PublicKey: initialMsg.PublicKey,
	}

	var joined bool
	for {
		if selectedRoom.First == nil {
			if joined {
				continue
			}
			if err := s.rooms.SetFirst(roomID, &client); err != nil {
				return nil, 0, "", errors.Wrap(err,
					fmt.Sprintf("failed to set first client (%s)", client.Addr),
				)
			}
			joined = true
		} else {
			if client.Addr == selectedRoom.First.Addr && selectedRoom.Second != nil {
				return keyExchange(selectedRoom, &client, room.FirstRole)
			}
		}

		if selectedRoom.Second == nil {
			if joined {
				continue
			}
			if err := s.rooms.SetSecond(roomID, &client); err != nil {
				return nil, 0, "", errors.Wrap(err,
					fmt.Sprintf("failed to set second client (%s)", client.Addr),
				)
			}
			joined = true
		} else {
			if client.Addr == selectedRoom.Second.Addr && selectedRoom.First != nil {
				return keyExchange(selectedRoom, &client, room.SecondRole)
			}
		}
	}
}

func keyExchange(selectedRoom *room.Room, client *room.Client, role room.Role) (*room.Client, room.RoomID, room.Role, error) {
	otherClient, err := selectedRoom.OtherClient(role)
	if err != nil {
		return nil, 0, "", errors.Wrap(err,
			fmt.Sprintf("failed to get recipient for client (%s)", client.Addr),
		)
	}

	keyExhangeMessage, err := dto.Make(dto.KeysExchange, dto.KeyExchangeMsg{
		PublicKey: otherClient.PublicKey,
	})
	if err != nil {
		return nil, 0, "", errors.Wrap(err,
			fmt.Sprintf("failed to make key exchange message from client (%s) to client (%s)",
				otherClient.Addr, client.Addr),
		)
	}

	log.Printf("Sent public key to %s (%s)", role, otherClient.Addr)
	if err := tcp.Send(client.Conn, keyExhangeMessage); err != nil {
		return nil, 0, "", errors.Wrap(err,
			fmt.Sprintf("failed to send key exchange message from client (%s) to client (%s)",
				otherClient.Addr, client.Addr),
		)
	}
	client.HavePubKeyRecipient = true

	if otherClient.HavePubKeyRecipient {
		keyExhangeMessage, err := dto.Make(dto.KeysExchange,
			dto.KeyExchangeMsg{PublicKey: client.PublicKey})
		if err != nil {
			return nil, 0, "", errors.Wrap(err,
				fmt.Sprintf("failed to make key exchange message from client (%s) to client (%s)",
					client.Addr, otherClient.Addr),
			)
		}

		log.Printf("Sent public key to client %s", otherClient.Addr)
		if err := tcp.Send(otherClient.Conn, keyExhangeMessage); err != nil {
			return nil, 0, "", errors.Wrap(err,
				fmt.Sprintf("failed to send key exchange message from client (%s) to client (%s)",
					client.Addr, otherClient.Addr),
			)
		}
	}

	return client, selectedRoom.ID, role, nil
}

func (s *Server) handleText(conn net.Conn, msg dto.Message) error {
	var textMsg dto.CypherMsg
	if err := json.Unmarshal(msg.Payload, &textMsg); err != nil {
		return errors.Wrap(err, "failed to unmarshall text message")
	}

	selectedRoom, err := s.rooms.GetRoom(room.RoomID(textMsg.RoomID))
	if err != nil {
		return errors.Wrap(err, "failed to get room")
	}

	clientAddr := conn.RemoteAddr().String()
	if selectedRoom.First != nil && selectedRoom.First.Addr != clientAddr &&
		selectedRoom.Second != nil && selectedRoom.Second.Addr != clientAddr {
		return fmt.Errorf("unexpected room")
	}

	bytes, err := json.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "failed to marshal message")
	}

	if selectedRoom.First != nil && selectedRoom.First.Addr == clientAddr {
		if selectedRoom.Second != nil {
			log.Printf("Send message from %s to %s", selectedRoom.First.Addr, selectedRoom.Second.Addr)
			if err := tcp.Send(selectedRoom.Second.Conn, bytes); err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed to send message to second (%s)", selectedRoom.Second.Addr))
			}
		}
	}

	if selectedRoom.Second != nil && selectedRoom.Second.Addr == clientAddr {
		if selectedRoom.First != nil {
			log.Printf("Send message from %s to %s", selectedRoom.Second.Addr, selectedRoom.First.Addr)
			if err := tcp.Send(selectedRoom.First.Conn, bytes); err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed to send message to first (%s)", selectedRoom.First.Addr))
			}
		}
	}

	return nil
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

func getServerCert(domain string) (*dto.Certificate, error) {
	certConn, err := net.Dial("tcp", "localhost:8081")
	if err != nil {
		return nil, errors.Wrap(err, "error connect cert server")
	}
	defer certConn.Close()

	getCertMsg, err := dto.Make(dto.GetCert, dto.GetCertMsg{Domain: domain})
	if err != nil {
		return nil, errors.Wrap(err, "failed to make get pub key cert server msg")
	}

	if err = tcp.Send(certConn, getCertMsg); err != nil {
		return nil, errors.Wrap(err, "failed to send domain to certification server")
	}

	var certBytes []byte
	if err = tcp.Read(bufio.NewReader(certConn), &certBytes); err != nil {
		return nil, errors.Wrap(err, "failed to read cert from certification server")
	}

	var cert dto.Certificate
	if err = json.Unmarshal(certBytes, &cert); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall cert pubkey")
	}

	return &cert, nil
}

func checkCert(cert *dto.Certificate, certServerPubKey *rsa.PublicKey, domain string) error {
	hash, err := rsa.HashSHA256(cert.Domain + cert.ExpiresIn)
	if err != nil {
		return errors.Wrap(err, "error hashing domain expiresIn certificate sum")
	}

	if !rsa.Verify(cert.Signature, hash, certServerPubKey) {
		return errors.New("certificate is fake")
	}

	if cert.Domain != domain {
		return errors.New("invalid domain")
	}

	return nil
}

func getCert(domain string) (*dto.Certificate, error) {
	pubkey, err := getCertPubKey()
	if err != nil {
		return nil, errors.Wrap(err, "error getting pub key from cert server")
	}

	cert, err := getServerCert(domain)
	if err != nil {
		return nil, errors.Wrap(err, "error getting certificate from cert server")
	}

	if err := checkCert(cert, pubkey, domain); err != nil {
		return nil, errors.Wrap(err, "failed to check certificate")
	}

	return cert, nil
}

func calculateSleepDuration(expirationTimeString string) (time.Duration, error) {
	expirationTime, err := time.Parse("2006-01-02 15:04:05", expirationTimeString)
	if err != nil {
		return 0, fmt.Errorf("ошибка парсинга даты истечения: %w", err)
	}
	return time.Until(expirationTime), nil
}

func (s *Server) updateCert() {
	for {
		sleepTime, err := calculateSleepDuration(s.cert.ExpiresIn)
		if err != nil {
			log.Printf("Failed to calculate sleep duration: %s", err.Error())
			return
		}

		time.Sleep(sleepTime)

		s.certMu.Lock()
		s.cert, err = getCert(s.domain)
		if err != nil {
			log.Printf("Failed to get certificate to update: %s", err.Error())
			return
		}
		s.certMu.Unlock()

		log.Printf("Certificate updated, expires in %s", s.cert.ExpiresIn)
	}
}
