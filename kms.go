package kms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"time"

	vkms "github.com/axieinfinity/ronin-kms-client/message"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

//go:generate protoc --go_out=message --go-grpc_out=message message/message.proto
const SuccessCode = 1

var ErrAccessDenied = errors.New("KMS VM access denied")

type KmsSign struct {
	connection  *grpc.ClientConn
	keyToken    []byte
	address     common.Address
	signTimeout int64
}

type KmsConfig struct {
	KeyTokenPath  string `json:"keyTokenPath"`
	SslCertPath   string `json:"sslCertPath"`
	KmsServerAddr string `json:"kmsServerAddr"`
	KmsSourceAddr string `json:"kmsSourceAddr"`
	SignTimeout   int64  `json:"signTimeout"`
}

func NewKmsSign(kmsConfig *KmsConfig) (*KmsSign, error) {
	keyToken, err := ioutil.ReadFile(kmsConfig.KeyTokenPath)
	if err != nil {
		log.Error("[KMS] Failed to read token key file", "error", err)
		return nil, err
	}

	sslCert, err := ioutil.ReadFile(kmsConfig.SslCertPath)
	if err != nil {
		log.Error("[KMS] Failed to read SSL certificate file", "error", err)
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(sslCert)
	tlsCfg := &tls.Config{RootCAs: certPool, InsecureSkipVerify: true}

	sourceAddr, err := net.ResolveTCPAddr("tcp", kmsConfig.KmsSourceAddr)
	if err != nil {
		log.Error("[KMS] Failed to resolve source address", "error", err)
		return nil, err
	}

	dialer := net.Dialer{
		LocalAddr: sourceAddr,
	}

	conn, err := grpc.Dial(kmsConfig.KmsServerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", s)
		}),
	)
	if err != nil {
		log.Error("[KMS] Failed to dial to KMS VM", "error", err)
		return nil, err
	}

	client := vkms.NewUserClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(kmsConfig.SignTimeout*int64(time.Millisecond)))
	defer cancel()
	resp, err := client.Sign(
		metadata.AppendToOutgoingContext(ctx, "vkms_data_type", "non-ether"),
		&vkms.SignRequest{
			KeyUsageToken: keyToken,
			Data:          []byte{},
		},
	)
	if err != nil {
		log.Error("[KMS] Failed to request signing", "error", err)
		return nil, err
	}
	if resp.Code != SuccessCode {
		log.Error("[KMS] KMS VM access denied")
		return nil, err
	}

	publicKey, err := crypto.SigToPub(crypto.Keccak256([]byte{}), resp.Signature)
	if err != nil {
		log.Error("[KMS] Failed to get KMS public key")
		return nil, err
	}
	address := crypto.PubkeyToAddress(*publicKey)
	log.Info("[KMS] Siging account", "address", address)

	return &KmsSign{
		connection:  conn,
		keyToken:    keyToken,
		address:     address,
		signTimeout: kmsConfig.SignTimeout,
	}, nil
}

// Sign function receives raw message, not hash of message
func (kmsSign *KmsSign) Sign(message []byte, dataType string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(kmsSign.signTimeout*int64(time.Millisecond)))
	defer cancel()

	resp, err := vkms.NewUserClient(kmsSign.connection).Sign(
		metadata.AppendToOutgoingContext(ctx, "vkms_data_type", dataType),
		&vkms.SignRequest{
			KeyUsageToken: kmsSign.keyToken,
			Data:          message,
		},
	)
	if err != nil {
		log.Error("[KMS] Failed to request signing", "error", err)
		return nil, err
	}
	if resp.Code != SuccessCode {
		log.Error("[KMS] KMS VM access denied")
		return nil, ErrAccessDenied
	}

	return resp.Signature, nil
}
