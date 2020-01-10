package main

import (
	"fmt"
	"net"
)

// Client is the structure describing the client connected to Postfix.
type Client struct {
	Name   string
	IP     net.IP
	Status string
	Sender string
}

// newClient initialises the properties of a new client.
func newClient() Client {
	client := Client{
		Name:   "",
		IP:     nil,
		Sender: "",
		Status: "",
	}
	return client
}

// String prints the name and IP of the client.
func (c Client) String() string {
	name := "unknown"
	ip := "unknown"
	if len(c.Name) > 0 {
		name = c.Name
	}
	if c.IP != nil {
		ip = c.IP.String()
	}
	return fmt.Sprintf("%s[%s]", name, ip)
}
