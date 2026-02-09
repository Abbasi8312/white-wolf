package whitewolf

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
)

// Encrypted payload: first 2 bytes = length (BE), then [nonce 12][ciphertext+tag].
// If length is 0, treat as passthrough (no proxy payload).

const lengthBytes = 2

// ReadFirstBlock reads the first 2 bytes (length of encrypted part) into first and returns that length.
func ReadFirstBlock(reader io.Reader, first *buf.Buffer) (encLen uint16, err error) {
	if _, err = first.ReadFullFrom(reader, lengthBytes); err != nil {
		return 0, err
	}
	encLen = binary.BigEndian.Uint16(first.BytesTo(lengthBytes))
	return encLen, nil
}

// ReadEncryptedPayload reads exactly encLen bytes (nonce + ciphertext) into the buffer.
func ReadEncryptedPayload(reader io.Reader, encLen uint16, b *buf.Buffer) error {
	if encLen == 0 {
		return nil
	}
	if _, err := b.ReadFullFrom(reader, int32(encLen)); err != nil {
		return err
	}
	return nil
}

// TryDecrypt decrypts the payload with the given AEAD. Returns (plaintext, nil) on success, (nil, err) on failure.
func TryDecrypt(aead cipher.AEAD, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+aead.Overhead() {
		return nil, errors.New("whitewolf: ciphertext too short")
	}
	nonce := ciphertext[:NonceSize]
	ct := ciphertext[NonceSize:]
	out := make([]byte, 0, len(ct)-aead.Overhead())
	return aead.Open(out, nonce, ct, nil)
}

// ParseDestination parses the inner plaintext: address + port (2) + rest.
// Returns destination and the remaining payload bytes after the header.
func ParseDestination(plaintext []byte) (net.Destination, []byte, error) {
	if len(plaintext) < 1+2 {
		return net.Destination{}, nil, errors.New("whitewolf: payload too short for address")
	}
	r := bytes.NewReader(plaintext)
	b := buf.New()
	defer b.Release()
	addr, port, err := addrParser.ReadAddressPort(b, r)
	if err != nil {
		return net.Destination{}, nil, err
	}
	rest, _ := io.ReadAll(r)
	return net.TCPDestination(addr, port), rest, nil
}

// WriteRequestHeader encodes destination and optional initial payload into the format:
// address + port (2) + payload. Used by client; server only parses.
func WriteRequestHeader(writer io.Writer, dest net.Destination, payload []byte) error {
	if err := addrParser.WriteAddressPort(writer, dest.Address, dest.Port); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := writer.Write(payload)
		return err
	}
	return nil
}

// SealChunk encrypts plaintext with aead and writes [2-byte length][12-byte nonce][ciphertext] to w.
// nonce must be 12 bytes and will be overwritten (caller can use incrementing nonce).
func SealChunk(aead cipher.AEAD, nonce []byte, plaintext []byte, w io.Writer) error {
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	if len(ciphertext) > 0xFFFF {
		return errors.New("whitewolf: chunk too large")
	}
	var lenBuf [lengthBytes]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(NonceSize+len(ciphertext)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(nonce); err != nil {
		return err
	}
	_, err := w.Write(ciphertext)
	return err
}

// OpenChunk reads [2-byte length][nonce][ciphertext] from r and decrypts. Returns plaintext or error.
func OpenChunk(aead cipher.AEAD, r io.Reader) ([]byte, error) {
	var lenBuf [lengthBytes]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	encLen := binary.BigEndian.Uint16(lenBuf[:])
	if encLen < NonceSize+uint16(aead.Overhead()) {
		return nil, errors.New("whitewolf: invalid chunk length")
	}
	buf := make([]byte, encLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return TryDecrypt(aead, buf)
}
