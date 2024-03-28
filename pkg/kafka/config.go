package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/IBM/sarama"
	"os"
)

var (
	kafkaUsername         string
	kafkaPassword         string
	brokers               *string
	topics                *string
	kafkaSecurityProtocol string
	kafkaSaslMechanism    string
	sslEnabled            bool
	sslCaLocation         string
	sslKeyLocation        string
	sslCertLocation       string
)

func GetConfig() *sarama.Config {
	config := sarama.NewConfig()
	if kafkaUsername != "" && kafkaPassword != "" {
		config.Net.SASL.Enable = true
		config.Net.SASL.User = kafkaUsername
		config.Net.SASL.Password = kafkaPassword
		config.Net.SASL.Mechanism = sarama.SASLMechanism(kafkaSaslMechanism)
	}
	// get tls cert, clientCA and rootCA for tls config
	clientCA := x509.NewCertPool()
	rootCA := x509.NewCertPool()

	tlsCert, err := os.ReadFile(sslCertLocation)
	if err != nil {
		fmt.Errorf("failed to read client certificate", err)
		return nil
	}
	tlsKey, err := os.ReadFile(sslKeyLocation)
	if err != nil {
		fmt.Errorf("failed to read client key", err)
		return nil
	}

	crt, err := tls.X509KeyPair(tlsCert, tlsKey)
	if err != nil {
		fmt.Errorf("failed to parse private key pair", err)
		return nil
	}
	ca, err := os.ReadFile(sslCaLocation)
	if err != nil {
		fmt.Errorf("failed to read CA certificate", err)
		return nil
	}
	clientCA.AppendCertsFromPEM(ca)
	rootCA.AppendCertsFromPEM(ca)

	if sslEnabled {
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
