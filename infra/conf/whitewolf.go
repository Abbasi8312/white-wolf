package conf

import (
	"encoding/base64"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/whitewolf"
	"google.golang.org/protobuf/proto"
)

// WhitewolfInboundConfig is inbound configuration for whitewolf.
type WhitewolfInboundConfig struct {
	SymmetricKey string `json:"symmetricKey"`
	FallbackDest string `json:"fallbackDest"`
}

// Build implements Buildable.
func (c *WhitewolfInboundConfig) Build() (proto.Message, error) {
	if c.SymmetricKey == "" {
		return nil, errors.New("whitewolf: empty symmetricKey")
	}
	key, err := base64.RawURLEncoding.DecodeString(c.SymmetricKey)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(c.SymmetricKey)
		if err != nil {
			return nil, errors.New("whitewolf: invalid symmetricKey encoding").Base(err)
		}
	}
	if len(key) != whitewolf.KeySize {
		return nil, errors.New("whitewolf: symmetricKey must be ", whitewolf.KeySize, " bytes, got ", len(key))
	}
	if c.FallbackDest == "" {
		return nil, errors.New("whitewolf: empty fallbackDest")
	}
	return &whitewolf.ServerConfig{
		SymmetricKey: key,
		FallbackDest: c.FallbackDest,
	}, nil
}

// WhitewolfClientConfig is outbound configuration for whitewolf.
type WhitewolfClientConfig struct {
	Address      *Address `json:"address"`
	Port         uint16   `json:"port"`
	SymmetricKey string   `json:"symmetricKey"`
}

// Build implements Buildable.
func (c *WhitewolfClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("whitewolf: server address is not set")
	}
	if c.Port == 0 {
		return nil, errors.New("whitewolf: invalid server port")
	}
	if c.SymmetricKey == "" {
		return nil, errors.New("whitewolf: empty symmetricKey")
	}
	key, err := base64.RawURLEncoding.DecodeString(c.SymmetricKey)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(c.SymmetricKey)
		if err != nil {
			return nil, errors.New("whitewolf: invalid symmetricKey encoding").Base(err)
		}
	}
	if len(key) != whitewolf.KeySize {
		return nil, errors.New("whitewolf: symmetricKey must be ", whitewolf.KeySize, " bytes, got ", len(key))
	}
	return &whitewolf.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
			User: &protocol.User{
				Account: serial.ToTypedMessage(&whitewolf.Account{SymmetricKey: key}),
			},
		},
	}, nil
}
