package whitewolf

import (
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount implements protocol.Account for whitewolf.
type MemoryAccount struct {
	SymmetricKey []byte
}

// AsAccount implements protocol.AsAccount.
func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{SymmetricKey: a.GetSymmetricKey()}, nil
}

// Equals implements protocol.Account.Equals.
func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if acc, ok := another.(*MemoryAccount); ok {
		if len(a.SymmetricKey) != len(acc.SymmetricKey) {
			return false
		}
		for i := range a.SymmetricKey {
			if a.SymmetricKey[i] != acc.SymmetricKey[i] {
				return false
			}
		}
		return true
	}
	return false
}

// ToProto implements protocol.Account.ToProto.
func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{SymmetricKey: a.SymmetricKey}
}
