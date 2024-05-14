package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"

	"github.com/neekrasov/end-to-end-encryption/pkg/room"
	"github.com/neekrasov/end-to-end-encryption/pkg/tcp"
	"github.com/pkg/errors"
)

type RoomManager interface {
	Create(id room.RoomID)
	GetRoom(id room.RoomID) (*room.Room, error)
	SetFirst(id room.RoomID, client *room.Client) error
	SetSecond(id room.RoomID, client *room.Client) error
	RemoveClient(addr string) bool
}

type Server struct {
	rooms RoomManager
}

func New(roomManager RoomManager) *Server {
	return &Server{rooms: roomManager}
}

func (s *Server) Serve() error {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		return fmt.Errorf("error starting server: %w", err)
	}
	log.Println("Server was started")

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
			if errors.Is(err, io.EOF) {
				addr := conn.RemoteAddr().String()
				s.rooms.RemoveClient(addr)
				log.Printf("Сlient %s disconnected", addr)
				return
			}
			log.Printf("Failed to read client message: %s", err.Error())
			return
		}

		var msg tcp.Message
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			log.Printf("Failed to unmarshall message: %s", err.Error())
			return
		}

		switch msg.Type {
		case tcp.Connect:
			client, roomID, position, err := s.handleInitial(conn, msg)
			if err != nil {
				log.Printf("failed to handle initial connect: %s", err.Error())
				return
			}

			log.Printf("Client %s joined to room %d on %s position", client.Addr, roomID, position)
		case tcp.Text:
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

func (s *Server) handleInitial(conn net.Conn, msg tcp.Message) (*room.Client, room.RoomID, room.Role, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("we was in panic: \n %v \n %v", string(debug.Stack()), fmt.Errorf("%v", r))
			return
		}
	}()

	var initialMsg tcp.InitialMessage
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

	keyExhangeMessage, err := tcp.MakeMessage(tcp.KeysExchange, tcp.KeyExchangeMessage{
		PublicKey: otherClient.PublicKey,
	})
	if err != nil {
		return nil, 0, "", errors.Wrap(err,
			fmt.Sprintf("failed to make key exchange message from client (%s) to client (%s)",
				otherClient.Addr, client.Addr),
		)
	}

	keyExhangeMessageBytes, err := json.Marshal(keyExhangeMessage)
	if err != nil {
		return nil, 0, "", errors.Wrap(err,
			fmt.Sprintf("failed to marshal key exchange message from client (%s) to client (%s)",
				otherClient.Addr, client.Addr),
		)
	}

	log.Printf("Sent public key to %s (%s)", role, otherClient.Addr)
	if err := tcp.Send(client.Conn, keyExhangeMessageBytes); err != nil {
		return nil, 0, "", errors.Wrap(err,
			fmt.Sprintf("failed to send key exchange message from client (%s) to client (%s)",
				otherClient.Addr, client.Addr),
		)
	}

	return client, selectedRoom.ID, role, nil
}

func (s *Server) handleText(conn net.Conn, msg tcp.Message) error {
	var textMsg tcp.TextMessage
	if err := json.Unmarshal(msg.Payload, &textMsg); err != nil {
		return errors.Wrap(err, "failed to unmarshall text message")
	}

	clientAddr := conn.RemoteAddr().String()
	roomID := room.RoomID(textMsg.Room)

	selectedRoom, err := s.rooms.GetRoom(roomID)
	if err != nil {
		return errors.Wrap(err, "failed to get room")
	}

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
