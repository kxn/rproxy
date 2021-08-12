package main

import (
	"io"
	"net"
)

const (
	tlsTypeRecordAlert                uint8 = 0x15
	tlsTypeRecordChangeCiperSpec      uint8 = 0x14
	tlsTypeRecordHandShake            uint8 = 0x16
	tlsTypeRecordApplicationData      uint8 = 0x17
	tlsTypeMessageHelloRequest        uint8 = 0
	tlsTypeMessageClientHello         uint8 = 1
	tlsTypeMessageServerHello         uint8 = 2
	tlsTypeMessageNewSessionTicket    uint8 = 4
	tlsTypeMessageEndOfEarlyData      uint8 = 5
	tlsTypeMessageEncryptedExtensions uint8 = 8
	tlsTypeMessageCertificate         uint8 = 0xb
	tlsTypeMessageServerKeyExchange   uint8 = 0xc
	tlsTypeMessageCertificateRequest  uint8 = 0xd
	tlsTypeMessageServerDone          uint8 = 0xe
	tlsTypeMessageCertificateVerify   uint8 = 0xf
	tlsTypeMessageClientKeyExchange   uint8 = 0x10
	tlsTypeMessageFinished            uint8 = 0x14 // 这个恰好和 ChangeCipherSpec 重复了
	tlsTypeMessageCertificateStatus   uint8 = 22
	tlsTypeMessageKeyUpdate           uint8 = 24
	tlsTypeMessageMessageHash         uint8 = 254
	extensionIDServerName             int   = 0
)

type tlsConn struct {
	conn          net.Conn
	readBuffer    []byte
	versionBuffer []byte
}

type tlsMessage struct {
	head        []byte
	data        []byte
	IsHandShake bool
	version     []byte // optional, used to keep tls version for handshake packet
}

func makeNetworkInt(d []byte) int {
	var ret int
	for _, c := range d {
		ret = (ret << 8) + int(c)
	}
	return ret
}

func writeNetworkInt(d []byte, v int) {
	for i := range d {
		d[len(d)-1-i] = byte(v % 256)
		v = v >> 8
	}
}

func newMessage(head []byte, data []byte, isHandShake bool) *tlsMessage {
	if isHandShake {
		if len(head) != 4 || makeNetworkInt(head[1:4]) != len(data) {
			logger.Errorw("Invalid handshake message data", "head", head, "data", data)
			return nil
		}
	} else {
		if len(head) != 5 || makeNetworkInt(head[3:5]) != len(data) {
			logger.Errorw("nvalid TLS record data", "head", head, "data", data)
			return nil
		}
	}
	ret := new(tlsMessage)
	ret.head = head
	ret.data = data
	ret.IsHandShake = isHandShake
	return ret
}

func (p *tlsMessage) Type() uint8 {
	return p.head[0]
}

func readWithlogging(logtype string, c net.Conn, data []byte) error {
	logger.Debugw("Read data", "type", logtype, "remote", c.RemoteAddr(), "len", len(data))
	if _, err := io.ReadFull(c, data); err != nil {
		logger.Warnw("Read failed", "type", logtype, "remote", c.RemoteAddr(), "err", err)
		return err
	}
	return nil
}

func writeWithlogging(logtype string, c net.Conn, data []byte) error {
	logger.Debugw("Write data", "type", logtype, "remote", c.RemoteAddr(), "len", len(data))
	if _, err := c.Write(data); err != nil {
		logger.Warnw("Write failed", "type", logtype, "remote", c.RemoteAddr(), "err", err)
		return err
	}
	return nil
}

func (c *tlsConn) ReadMessage() (*tlsMessage, error) {
	if len(c.readBuffer) == 0 {
		// Nothing in buffer, try to read somthing
		head := make([]byte, 5)
		if err := readWithlogging("head", c.conn, head); err != nil {
			return nil, err
		}
		// check  TLS version
		if head[1] != 3 {
			logger.Warnf("Invalid TLS version %d,%d from remote %s", head[1], head[2], c.conn.RemoteAddr().String())
			return nil, errInvalidTLSPacket
		}

		c.versionBuffer = make([]byte, 2)
		c.versionBuffer[0] = head[1]
		c.versionBuffer[1] = head[2]

		logger.Debugf("tls record length %d", makeNetworkInt(head[3:5]))
		if head[0] == tlsTypeRecordAlert || head[0] == tlsTypeRecordChangeCiperSpec || head[0] == tlsTypeRecordApplicationData {
			// Read rest and create a message immediately
			body := make([]byte, makeNetworkInt(head[3:5]))
			if err := readWithlogging("body", c.conn, body); err != nil {
				return nil, err
			}
			return newMessage(head, body, false), nil
		}
		if head[0] != tlsTypeRecordHandShake {
			// Invalid TLS packet, reject
			logger.Warn("Expect handshake from %s, got a %d, rejecting", c.conn.RemoteAddr().String(), head[0])
			return nil, errInvalidTLSPacket
		}
		// Otherwise, read the tls body into readbuffer
		c.readBuffer = make([]byte, makeNetworkInt(head[3:5]))
		if err := readWithlogging("message body", c.conn, c.readBuffer); err != nil {
			logger.Warn("Read handshake body failed in Readmessage")
			return nil, err
		}
	}
	logger.Debugf("About to parse read buffer %v", c.readBuffer)
	if len(c.readBuffer) < 4 {
		logger.Warn("Handshake message shorter than 4 bytes")
		return nil, errInvalidTLSPacket
	}
	// Parse a handshake message out of the readbuffer, handshake header is useless though
	// sanity check, handshake type should be something known
	switch c.readBuffer[0] {
	case tlsTypeMessageCertificate:
	case tlsTypeMessageCertificateRequest:
	case tlsTypeMessageClientHello:
	case tlsTypeMessageCertificateVerify:
	case tlsTypeMessageClientKeyExchange:
	case tlsTypeMessageFinished:
	case tlsTypeMessageHelloRequest:
	case tlsTypeMessageServerDone:
	case tlsTypeMessageServerHello:
	case tlsTypeMessageServerKeyExchange:
	case tlsTypeMessageNewSessionTicket:
	case tlsTypeMessageEncryptedExtensions:
	case tlsTypeMessageEndOfEarlyData:
	case tlsTypeMessageKeyUpdate:
	case tlsTypeMessageMessageHash:
	case tlsTypeMessageCertificateStatus:
		break
	default:
		logger.Warnf("Invalid type of TLS handshake %d", c.readBuffer[0])
		return nil, errInvalidTLSPacket
	}
	bodylen := makeNetworkInt(c.readBuffer[1:4])
	if len(c.readBuffer) < bodylen+4 {
		// TODO: This is not an errror, just hard to handle, return failure for now
		logger.Error("Cross record handshake message, take it as an error now")
		return nil, errInvalidTLSPacket
	}
	head := c.readBuffer[0:4]
	body := c.readBuffer[4 : 4+bodylen]
	c.readBuffer = c.readBuffer[4+bodylen:]
	ret := newMessage(head, body, true)
	ret.version = c.versionBuffer
	logger.Debugf("Received a type %d packet from %v, %d bytes left in readbuffer", ret.Type(), c.conn.RemoteAddr(), len(c.readBuffer))
	return ret, nil
}

func (p *tlsMessage) LogForError(s string) {
	if p.IsHandShake {
		logger.Debugw("Handshake packet", "error", s, "type", p.Type(), "len", len(p.data), "data", p.data)
	} else {
		logger.Debugw("TLS record", "error", s, "type", p.Type(), "len", len(p.data), "data", p.data)
	}
}

func (c *tlsConn) WriteMessage(m *tlsMessage) error {
	if m.IsHandShake {
		// 自己做一个 TLS handshake packet
		head := make([]byte, 5)
		head[0] = tlsTypeRecordHandShake
		if len(m.version) == 2 {
			head[1] = m.version[0]
			head[2] = m.version[1]
		} else {
			head[1] = 3
			head[2] = 3
		}
		writeNetworkInt(head[3:5], len(m.head)+len(m.data))
		err := writeWithlogging("head", c.conn, head)
		if err != nil {
			return err
		}
		err = writeWithlogging("message head", c.conn, m.head)
		if err != nil {
			return err
		}
		err = writeWithlogging("message body", c.conn, m.data)
		if err != nil {
			return err
		}
	} else {
		// TLS Record 比较简单，直接把 head 和 body 都写出去就好了
		err := writeWithlogging("head", c.conn, m.head)
		if err != nil {
			return err
		}
		err = writeWithlogging("body", c.conn, m.data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *tlsMessage) ExtractSNI() (string, error) {
	if !p.IsHandShake || len(p.head) != 4 || p.head[0] != tlsTypeMessageClientHello {
		p.LogForError("Invalid client hello ")
		return "", errInvaildClientHello
	}
	logger.Debugf("About to parse client hello len %d, %v", len(p.data), p.data)
	data := p.data
	if len(data) < 2+32+1 { // 2 bytes TLS version, 32 bytes random, 1 byte sessionid length
		logger.Warnf("Clienthello length incorrect, less than 2 bytes TLS version + 32 bytes random + 1 byte sessionid length")
		return "", errInvaildClientHello
	}
	sessiondIDLen := int(data[2+32])
	if sessiondIDLen > 32 || len(data) < 2+32+1+sessiondIDLen {
		logger.Warnf("Invalid session id length %d or invalid packet length %d", sessiondIDLen, len(data))
		return "", errInvaildClientHello
	}
	data = data[2+31+1+sessiondIDLen+1:]
	logger.Debugf("Skipping length %d (2+31+1+%d)", 2+31+1+sessiondIDLen, sessiondIDLen)
	if len(data) < 2 {
		logger.Warnf("packet length not enough for len of ciphersuitelen")
		return "", errInvaildClientHello
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := makeNetworkInt(data[0:2])
	logger.Debugf("Ciphersuite len %d, packet left %d", cipherSuiteLen, len(data))
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		logger.Warnf("Invalid ciphersuite len")
		return "", errInvaildClientHello
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		logger.Warnf("packet length not enough for len of compressionmethods len")
		return "", errInvaildClientHello
	}
	compressionMethodsLen := int(data[0])
	logger.Debugf("CompressionMethodsLen %d, packet left %d", compressionMethodsLen, len(data))
	if len(data) < 1+compressionMethodsLen {
		logger.Warnf("Invalid compressionmethods len")
		return "", errInvaildClientHello
	}
	data = data[1+compressionMethodsLen:]

	serverName := ""

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		logger.Debug("Empty extension, hence can not extract SNI name")
		return "", nil
	}
	if len(data) < 2 {
		logger.Warn("packet length not enough for len of extensions len")
		return "", errInvaildClientHello
	}
	extensionsLength := makeNetworkInt(data[0:2])
	logger.Debugf("extension len %d, packet left %d", extensionsLength, len(data))

	data = data[2:]
	if extensionsLength != len(data) {
		logger.Warnf("Invalid extension length %d, packet left %d", extensionsLength, len(data))
		return "", errInvaildClientHello
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return "", errInvaildClientHello
		}
		extension := makeNetworkInt(data[0:2])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return "", errInvaildClientHello
		}

		switch extension {
		case extensionIDServerName:
			if length < 2 {
				return "", errInvaildClientHello
			}
			numNames := makeNetworkInt(data[0:2])
			d := data[2:]
			for i := 0; i < numNames; i++ {
				if len(d) < 3 {
					return "", errInvaildClientHello
				}
				nameType := d[0]
				nameLen := makeNetworkInt(d[1:3])
				d = d[3:]
				if len(d) < nameLen {
					return "", errInvaildClientHello
				}
				if nameType == 0 {
					serverName = string(d[0:nameLen])
					break
				}
				d = d[nameLen:]
			}
		}
		data = data[length:]
	}
	logger.Debugf("Parsed servername %s", serverName)
	return serverName, nil
}

func (c *tlsConn) copyConn(srcConn *tlsConn) error {
	// 这个函数里面关闭源 conn
	defer srcConn.conn.Close()
	// 如果 buffer 里面还有 handshake message, 把它们发送出去，然后开始 io.Copy
	for {
		if len(srcConn.readBuffer) == 0 {
			break
		}
		p, err := srcConn.ReadMessage()
		if err != nil {
			return err
		}
		err = c.WriteMessage(p)
		if err != nil {
			// 这里写操作出错，所以要强制 close dst 的 conn, 至于它会不会在另一边的 copyConn 里面挂掉这个我就懒得管了
			c.conn.Close()
			return err
		}
	}
	_, err := io.Copy(c.conn, srcConn.conn)
	return err
}
