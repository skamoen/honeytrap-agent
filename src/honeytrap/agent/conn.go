package agent

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"

	"github.com/golang/protobuf/proto"

	protocol "honeytrap/agent/protocol"
)

type conn struct {
	net.Conn
	sc    ServiceConfig
	agent *Agent
}

func (c *conn) Dial(network, addr string) (net.Conn, error) {
	if c.agent.config.TLS.Enabled {
		return tls.Dial(network, addr, &tls.Config{})
	}

	return net.Dial(network, addr)
}

func (c *conn) serve() {
	defer c.Close()

	localAddr := c.LocalAddr().String()
	remoteAddr := c.RemoteAddr().String()
	token := c.agent.config.Token

	log.Debug("Forwarding connection %s to %s.", localAddr, c.sc.Host)

	cc, err := c.Dial("tcp", c.sc.Host)
	if err != nil {
		log.Error("Forwarding failed: %s", err.Error())
		return
	}

	defer cc.Close()

	message := protocol.Message{
		LocalAddress:  &localAddr,
		RemoteAddress: &remoteAddr,
		Token:         &token,
	}

	data, err := proto.Marshal(&message)
	if err != nil {
		log.Fatal("Marshaling error: %s", err.Error())
		return
	}

	binary.Write(cc, binary.LittleEndian, int32(len(data)))
	cc.Write(data)

	go io.Copy(c, cc)
	io.Copy(cc, c)
}
