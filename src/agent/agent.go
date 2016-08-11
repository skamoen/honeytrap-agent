package agent

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/honeytrap/agent/src/protocol"

	"github.com/golang/protobuf/proto"
)

type Agent struct {
	config *Config
}

func New(config *Config) *Agent {
	return &Agent{config}
}

func (a *Agent) newConn(sc ServiceConfig, rw net.Conn) (c *conn, err error) {
	c = &conn{rw, sc, a}
	return c, nil
}

func (a *Agent) serv(sc ServiceConfig, l net.Listener) error {
	defer l.Close()

	for {
		// TODO: Actually, should only accept if client connection has been built.
		rw, err := l.Accept()
		if err != nil {
			log.Error("Error while accepting connection: %s", err.Error())
			continue
		}

		c, err := a.newConn(sc, rw)
		if err != nil {
			continue
		}

		go c.serve()
	}
}

func (a *Agent) startPing() {
	go func() {
		for {
			log.Debug("Yep, still alive")

			if err := a.ping(); err != nil {
				log.Error("Ping failed: %s", err.Error())
			}

			<-time.After(time.Second * 60)
		}
	}()
}

func localIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() == nil {
				continue
			}

			return ipnet.IP.String()
		}
	}
	return ""
}

func (a *Agent) ping() error {
	cc, err := net.DialTimeout("tcp", a.config.Host, time.Second*30)
	if err != nil {
		return err
	}

	defer cc.Close()

	localIP := localIP()
	token := a.config.Token

	message := protocol.PingMessage{
		LocalAddress: &localIP,
		Token:        &token,
	}

	data, err := proto.Marshal(&message)
	if err != nil {
		return err
	}

	binary.Write(cc, binary.LittleEndian, int32(MessageTypePing))
	binary.Write(cc, binary.LittleEndian, int32(len(data)))
	cc.Write(data)
	return nil
}

func (a *Agent) Start() {
	log.Info("Honeytrap Agent started.")

	a.startPing()

	for _, sc := range a.config.Services {
		log.Info("Listener started for: %s(%s) to %s", sc.Address, sc.Protocol, sc.Host)
		l, err := net.Listen("tcp", sc.Address)
		if err != nil {
			log.Error("Could not start service %s: %s", sc.Protocol, err.Error())
			continue
		}

		go a.serv(sc, l)
	}
}
