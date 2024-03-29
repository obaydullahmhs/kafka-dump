package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"

	"github.com/IBM/sarama"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Brokers          []string
	Topics           string
	UserName         string
	Password         string
	SecurityProtocol string
	SaslMechanism    string
	CaLocation       string
	CertLocation     string
	KeyLocation      string
}

func NewConfig(brokers []string,
	topics string,
	userName string,
	password string,
	securityProtocol string,
	saslMechanism string,
	caLocation string,
	certLocation string,
	keyLocation string) *Config {
	return &Config{
		Brokers:          brokers,
		Topics:           topics,
		UserName:         userName,
		Password:         password,
		SecurityProtocol: securityProtocol,
		SaslMechanism:    saslMechanism,
		CaLocation:       caLocation,
		CertLocation:     certLocation,
		KeyLocation:      keyLocation,
	}
}

func (c *Config) GetConfig() *sarama.Config {
	log := logrus.New()
	config := sarama.NewConfig()
	if strings.Contains(c.SecurityProtocol, "SASL") {
		config.Net.SASL.Enable = true
		config.Net.SASL.User = c.UserName
		config.Net.SASL.Password = c.Password
		config.Net.SASL.Mechanism = sarama.SASLMechanism(c.SaslMechanism)
	}
	// get tls cert, clientCA and rootCA for tls config
	clientCA := x509.NewCertPool()
	rootCA := x509.NewCertPool()

	tlsCert, err := os.ReadFile(c.CertLocation)
	if err != nil {
		log.Error("failed to read client certificate", err)
		return nil
	}
	tlsKey, err := os.ReadFile(c.KeyLocation)
	if err != nil {
		log.Error("failed to read client key", err)
		return nil
	}

	crt, err := tls.X509KeyPair(tlsCert, tlsKey)
	if err != nil {
		log.Error("failed to parse private key pair", err)
		return nil
	}
	ca, err := os.ReadFile(c.CaLocation)
	if err != nil {
		log.Error("failed to read CA certificate", err)
		return nil
	}
	clientCA.AppendCertsFromPEM(ca)
	rootCA.AppendCertsFromPEM(ca)

	if strings.Contains(c.SecurityProtocol, "SSL") {
		config.Net.TLS.Enable = true
		config.Net.TLS.Config = &tls.Config{
			Certificates: []tls.Certificate{crt},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCA,
			RootCAs:      rootCA,
			MaxVersion:   tls.VersionTLS13,
		}
	}

	return config
}
