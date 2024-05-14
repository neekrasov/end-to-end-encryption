PHONY .PHONY: client
client:
	go run cmd/client/main.go

 .PHONY: server
server:
	go run cmd/server/main.go