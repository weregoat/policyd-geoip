package main

import (
	"fmt"
	"net"
	"strings"
)

// Client is the structure describing the client connected to Postfix.
type Client struct {
	Name         string
	IP      net.IP
	SenderDomain string
}

// String prints the name and IP of the client.
func (c *Client) String() string {
	name := "unknown"
	address := "unknown"
	if len(c.Name) > 0 {
		name = c.Name
	}
	if c.IP != nil {
		address = c.IP.String()
	}
	return fmt.Sprintf("%s[%s]", name, address)
}

// parseLine parses the line with the attributes from Postfix.
func (c *Client) parseLine(line string) {
	key, value := split(line, "=")
	value = strings.ToLower(strings.TrimSpace(value))
	key = strings.ToLower(strings.TrimSpace(key))
	if len(value) > 0 {
		switch key {
		case "client_address":
			ip := net.ParseIP(value)
			if ip != nil {
				c.IP = ip
			}
		case "client_name", "reverse_client_name":
			if value != "unknown" && len(c.Name) == 0 {
				c.Name = value
			}
		case "sender":
			_, domainAddress := split(value, "@")
			c.SenderDomain = domainAddress
		}
	}
}