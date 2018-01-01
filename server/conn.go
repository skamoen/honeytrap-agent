package server

import (
	"io"
	"net"
)

const (
	MessageTypeHello uint8 = 0x0
	MessageTypePing        = 0x2
)

type conn struct {
	net.Conn

	out  chan []byte
	host string

	agent *Agent
}

func (c *conn) Close() {
	c.agent.in <- EOF{
		Laddr: c.LocalAddr(),
		Raddr: c.RemoteAddr(),
	}

	c.Conn.Close()
}

func (c *conn) serve() {
	log.Debugf("Serving connection from %s => %s", c.RemoteAddr().String(), c.LocalAddr().String())
	// TODO: add inactivity timeout
	defer c.Close()
	defer log.Debugf("Closing connection from %s => %s", c.RemoteAddr().String(), c.LocalAddr().String())

	c.agent.in <- Hello{
		Token: c.agent.token,
		Laddr: c.LocalAddr(),
		Raddr: c.RemoteAddr(),
	}

	go func() {
		for buf := range c.out {
			_, err := c.Write(buf)
			if err == io.EOF {
				log.Debugf("EOF on connection write from %s => %s", c.RemoteAddr().String(), c.LocalAddr().String())
				return
			} else if err != nil {
				log.Error(err.Error())
				break
			}
		}
	}()

	func() {
		buf := make([]byte, 32*1024)

		for {
			nr, er := c.Read(buf)
			if er == io.EOF {
				log.Debugf("EOF on connection read from %s => %s", c.RemoteAddr().String(), c.LocalAddr().String())
				return
			} else if er != nil {
				log.Error(er.Error())
				break
			} else if nr == 0 {
				continue
			}

			c.agent.in <- ReadWrite{
				Laddr:   c.LocalAddr(),
				Raddr:   c.RemoteAddr(),
				Payload: buf[:nr],
			}
		}

	}()
}
