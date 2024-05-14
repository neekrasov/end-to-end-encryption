package room

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/neekrasov/end-to-end-encryption/pkg/rsa"
)

type (
	RoomID int
	Role   string

	Client struct {
		Addr      string
		Conn      net.Conn
		PublicKey *rsa.PublicKey
	}

	Room struct {
		ID     RoomID
		First  *Client
		Second *Client
	}

	RoomManager struct {
		rooms map[RoomID]*Room
		mu    sync.RWMutex
	}
)

const (
	FirstRole  Role = "first"
	SecondRole Role = "second"
)

func New() *RoomManager {
	return &RoomManager{rooms: make(map[RoomID]*Room)}
}

func (rm *RoomManager) Create(id RoomID) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.rooms[id] = &Room{ID: id}
}

func (rm *RoomManager) SetFirst(id RoomID, client *Client) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	room, ok := rm.rooms[id]
	if !ok {
		return fmt.Errorf("failed to get room by id %d", id)
	}

	room.First = client

	return nil
}

func (rm *RoomManager) SetSecond(id RoomID, client *Client) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	room, ok := rm.rooms[id]
	if !ok {
		return fmt.Errorf("failed to get room by id %d", id)
	}

	room.Second = client

	return nil
}

func (rm *RoomManager) GetRoom(id RoomID) (*Room, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	room, ok := rm.rooms[id]
	if !ok {
		return nil, fmt.Errorf("failed to get room by id %d", id)
	}

	return room, nil
}

func (rm *RoomManager) RemoveClient(addr string) bool {
	var removed bool
	for _, v := range rm.rooms {
		if v.First != nil && v.First.Addr == addr {
			v.First = nil
			removed = true
		} else if v.Second != nil && v.Second.Addr == addr {
			v.Second = nil
			removed = true
		}
	}

	return removed
}

func (r *Room) OtherClient(role Role) (*Client, error) {
	switch role {
	case FirstRole:
		return r.Second, nil
	case SecondRole:
		return r.First, nil
	}

	return nil, errors.New("unexpected role")
}
