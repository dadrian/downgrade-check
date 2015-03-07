package main

import (
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/dadrian/downgrade-check/ztools/x509"
	"github.com/dadrian/downgrade-check/ztools/ztls"
	"github.com/zmap/zgrab/ztools/zlog"
)

type Flags struct {
	CertificateChainPath string
	KeyPath              string
	LogFileName          string
	ListenAddress        string
	ExportKeyPath        string
	IECompatible         bool
}

var flags Flags

func init() {
	flag.StringVar(&flags.CertificateChainPath, "certificate", "cert_chain.pem", "Path to certificate chain (PEM encoded)")
	flag.StringVar(&flags.KeyPath, "key", "key.pem", "Path to key corresponding to certificate (PEM encoded, decrypted)")
	flag.StringVar(&flags.ListenAddress, "listen-address", "127.0.0.1:443", "ip:port to listen on")
	flag.StringVar(&flags.LogFileName, "log-file", "-", "defaults to stderr")
	flag.StringVar(&flags.ExportKeyPath, "export-key", "export-key.pem", "Path to 512-bit key")
	flag.BoolVar(&flags.IECompatible, "ie-compatible", false, "set to be compatible with IE11 (a.k.a. don't use TLS1.2)")
	flag.Parse()
}

type DowngradeLog struct {
	Host       string             `json:"ip_address"`
	Time       string             `json:"time"`
	Vulnerable bool               `json:"vulnerable"`
	Request    string             `json:"request,omitempty"`
	Ciphers    []ztls.CipherSuite `json:"ciphers,omitempty"`
	RawHello   []byte             `json:"raw_hello"`
}

var logChan chan DowngradeLog

func downgrade(c *ztls.Conn) error {
	defer c.Close()
	t := time.Now()
	deadline := t.Add(time.Second * 30)
	c.SetDeadline(deadline)
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	entry := DowngradeLog{
		Host: host,
		Time: t.Format(time.RFC3339),
	}
	handshakeErr := c.Handshake()
	entry.Ciphers = c.ClientCiphers()
	entry.RawHello = c.ClientHelloRaw()
	if handshakeErr != nil {
		logChan <- entry
		return handshakeErr
	}
	entry.Vulnerable = true
	buf := make([]byte, 1024)
	n, _ := c.Read(buf)
	entry.Request = string(buf[0:n])
	c.Write([]byte("HTTP/1.1 200 OK\r\n"))
	c.Write([]byte("Connection: close\r\n"))
	c.Write([]byte("Content-Type: text/plain; charset=us/ascii\r\n"))
	c.Write([]byte("Content-Length: 11\r\n"))
	c.Write([]byte("\r\n"))
	c.Write([]byte("VULNERABLE!"))
	logChan <- entry
	return nil
}

func main() {
	tlsConfig := ztls.Config{}
	cert, certErr := ztls.LoadX509KeyPair(flags.CertificateChainPath, flags.KeyPath)
	if certErr != nil {
		zlog.Fatal(certErr.Error())
	}
	tlsConfig.Certificates = []ztls.Certificate{cert}
	tlsConfig.SessionTicketsDisabled = true
	tlsConfig.PreferServerCipherSuites = true
	tlsConfig.MaxVersion = ztls.VersionTLS12
	if flags.IECompatible {
		tlsConfig.MaxVersion = ztls.VersionTLS11
	}

	encodedKey, readKeyErr := ioutil.ReadFile(flags.ExportKeyPath)
	if readKeyErr != nil {
		zlog.Fatal(readKeyErr.Error())
	}
	pemBlock, _ := pem.Decode(encodedKey)

	exportKey, decodeKeyErr := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if decodeKeyErr != nil {
		zlog.Fatal(decodeKeyErr.Error())
	}
	if exportKey.N.BitLen() != 512 {
		zlog.Fatal("export key is not 512 bits")
	}
	tlsConfig.ExportKey = exportKey

	logFile := os.Stderr
	if flags.LogFileName != "-" {
		f, err := os.Create(flags.LogFileName)
		if err != nil {
			zlog.Fatal(err.Error())
		}
		logFile = f
	}
	logChan = make(chan DowngradeLog, 1024)
	go func() {
		encoder := json.NewEncoder(logFile)
		for {
			entry := <-logChan
			encoder.Encode(entry)
		}
	}()

	listener, err := ztls.Listen("tcp", flags.ListenAddress, &tlsConfig)
	if err != nil {
		zlog.Fatal(err.Error())
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			zlog.Error(err.Error())
			continue
		}
		c := conn.(*ztls.Conn)
		go downgrade(c)
	}
}
