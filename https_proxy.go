package main

import (
	"net"
)

type HTTPSProxy struct {
	rules  *ForwardRules
	listen string
}

func NewHTTPSProxy(r *ForwardRules, listen string) *HTTPSProxy {
	return &HTTPSProxy{
		rules:  r,
		listen: listen,
	}
}

func (c *HTTPSProxy) RunConnection(HTTPSProxyConn *tlsConn, remoteHost string, pendingMessage *tlsMessage) error {
	defer HTTPSProxyConn.conn.Close()
	if _, _, err := net.SplitHostPort(remoteHost); err != nil {
		remoteHost = net.JoinHostPort(remoteHost, "443")
	}
	conn, err := dialer.Dial("tcp", remoteHost)
	if err != nil {
		logger.Infow("remote connect fail", "remote", remoteHost, "err", err)
		return err
	}
	defer conn.Close()
	serverConn := &tlsConn{
		conn:          conn,
		readBuffer:    []byte{},
		versionBuffer: []byte{},
	}

	if err := serverConn.WriteMessage(pendingMessage); err != nil {
		logger.Infof("write pending message to %s failed in RunConnection", serverConn.conn.RemoteAddr())
		return err
	}
	go serverConn.copyConn(HTTPSProxyConn)
	return HTTPSProxyConn.copyConn(serverConn)
}

func (c *HTTPSProxy) Serve(conn net.Conn) error {
	defer conn.Close()
	clientConn := &tlsConn{
		conn:          conn,
		readBuffer:    []byte{},
		versionBuffer: []byte{},
	}
	p, err := clientConn.ReadMessage()
	if err != nil {
		logger.Warnf("Read HTTPSProxyhello from %s failed, error %v, exiting", conn.RemoteAddr().String(), err)
		return err
	}
	logger.Debugf("Got a packet %v, %d", p.IsHandShake, p.Type())
	if p.IsHandShake && p.Type() == tlsTypeMessageClientHello {
		serverName, err := p.ExtractSNI()
		if err != nil {
			return err
		}
		if !c.rules.IsHostAllowed(serverName) {
			return errTargetRejected
		}
		LogAccess("https", conn.RemoteAddr().String(), serverName)
		return c.RunConnection(clientConn, serverName, p)
	}
	logger.Warnf("Non Clienthello packet from %s", conn.RemoteAddr().String())
	return errInvalidTLSProtocol
}

func (c *HTTPSProxy) Start() error {
	l, err := net.Listen("tcp", c.listen)
	if err != nil {
		logger.Fatalf("Unable to listen %s, %v", c.listen, err)
		return err
	}
	logger.Infof("Initialize ok, start serving https at %v", c.listen)
	go func() {
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				logger.Warnf("Error when accepting, error %v", err)
				continue
			}
			logger.Debugf("Received connection from %s", conn.RemoteAddr().String())
			go c.Serve(conn)
		}
	}()
	return nil
}
