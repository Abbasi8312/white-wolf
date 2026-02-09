package whitewolf

import (
	"github.com/xtls/xray-core/common/errors"
)

const (
	// AES-GCM key size in bytes.
	KeySize = 32
	// Nonce size for AES-GCM.
	NonceSize = 12
)

// Key returns the symmetric key, validating length.
func (c *ServerConfig) Key() ([]byte, error) {
	key := c.GetSymmetricKey()
	if len(key) != KeySize {
		return nil, errors.New("whitewolf: symmetric_key must be ", KeySize, " bytes, got ", len(key))
	}
	return key, nil
}
