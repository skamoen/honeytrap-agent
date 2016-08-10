package agent

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/golang/protobuf/proto"

	protocol "github.com/honeytrap/agent/agent/protocol"
)

const (
	MessageTypeForward = 0x1
	MessageTypePing    = 0x2
)

type conn struct {
	net.Conn
	sc    ServiceConfig
	agent *Agent
}

func (c *conn) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	if c.agent.config.TLS.Enabled {
		return tls.DialWithDialer(
			&net.Dialer{Timeout: timeout},
			network,
			addr,
			&tls.Config{},
		)
	}

	return net.DialTimeout(network, addr, timeout)
}

func (c *conn) serve() {
	// TODO: add inactivity timeout
	defer c.Close()

	defer func() {
		log.Debug("Connection closed.")
	}()

	localAddr := c.LocalAddr().String()
	remoteAddr := c.RemoteAddr().String()
	token := c.agent.config.Token

	log.Debug("Forwarding connection %s to %s.", localAddr, c.sc.Host)

	// TODO: make configurabele timeout
	cc, err := c.DialTimeout("tcp", c.sc.Host, time.Second*30)
	if err != nil {
		log.Error("Forwarding failed: %s", err.Error())
		return
	}

	defer cc.Close()

	message := protocol.PayloadMessage{
		LocalAddress:  &localAddr,
		RemoteAddress: &remoteAddr,
		Token:         &token,
		Protocol:      &c.sc.Protocol,
	}

	data, err := proto.Marshal(&message)
	if err != nil {
		log.Fatal("Marshaling error: %s", err.Error())
		return
	}

	binary.Write(cc, binary.LittleEndian, int32(MessageTypeForward))
	binary.Write(cc, binary.LittleEndian, int32(len(data)))
	cc.Write(data)

	// add gzip?, or are protocols efficient enough

	go func() {
		_, err := io.Copy(c, cc)
		if err != nil {
			log.Info(err.Error())
		}
	}()

	_, err = io.Copy(cc, c)
	if err != nil {
		log.Info(err.Error())
	}
}
