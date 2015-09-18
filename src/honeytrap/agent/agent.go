package agent

import "net"

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

func (a *Agent) Start() {
	log.Info("Honeytrap Agent started.")

	for name, sc := range a.config.Services {
		log.Info("Listener started for: %s(%s) to %s", sc.Address, name, sc.Host)
		l, err := net.Listen("tcp", sc.Address)
		if err != nil {
			log.Error("Could not start service %s: %s", name, err.Error())
			continue
		}

		go a.serv(sc, l)
	}
}
