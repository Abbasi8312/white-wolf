package whitewolf

import (
	"testing"
)

func TestConfigKey(t *testing.T) {
	validKey := make([]byte, KeySize)
	config := &ServerConfig{SymmetricKey: validKey}
	key, err := config.Key()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeySize {
		t.Errorf("key len = %d", len(key))
	}
	// Wrong size
	configShort := &ServerConfig{SymmetricKey: make([]byte, 16)}
	_, err = configShort.Key()
	if err == nil {
		t.Error("expected error for short key")
	}
	configNil := &ServerConfig{}
	_, err = configNil.Key()
	if err == nil {
		t.Error("expected error for nil key")
	}
}
