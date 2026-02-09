package whitewolf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func TestReadFirstBlock(t *testing.T) {
	// encLen = 0 (passthrough)
	r := bytes.NewReader([]byte{0, 0})
	first := buf.New()
	defer first.Release()
	encLen, err := ReadFirstBlock(r, first)
	if err != nil {
		t.Fatal(err)
	}
	if encLen != 0 {
		t.Errorf("encLen = %d, want 0", encLen)
	}
	// encLen = 100
	r2 := bytes.NewReader([]byte{0, 100})
	first2 := buf.New()
	defer first2.Release()
	encLen2, err := ReadFirstBlock(r2, first2)
	if err != nil {
		t.Fatal(err)
	}
	if encLen2 != 100 {
		t.Errorf("encLen = %d, want 100", encLen2)
	}
}

func TestTryDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	plaintext := []byte("hello")
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	blob := append(nonce, ciphertext...)
	out, err := TryDecrypt(aead, blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello" {
		t.Errorf("got %q", out)
	}
	// invalid (too short)
	_, err = TryDecrypt(aead, []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short ciphertext")
	}
	// wrong key
	key2 := make([]byte, KeySize)
	rand.Read(key2)
	block2, _ := aes.NewCipher(key2)
	aead2, _ := cipher.NewGCM(block2)
	_, err = TryDecrypt(aead2, blob)
	if err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}

func TestParseDestination(t *testing.T) {
	// IPv4: type=1, 4 bytes, port 2 bytes -> 1+4+2=7 bytes
	// 1 (IPv4) + 127.0.0.1 (4) + port 443 (0x01 0xBB)
	payload := []byte{
		1, 127, 0, 0, 1,
		0x01, 0xBB,
	}
	dest, rest, err := ParseDestination(payload)
	if err != nil {
		t.Fatal(err)
	}
	if dest.Address.String() != "127.0.0.1" || dest.Port.Value() != 443 {
		t.Errorf("dest = %v:%d", dest.Address, dest.Port.Value())
	}
	if len(rest) != 0 {
		t.Errorf("rest = %v", rest)
	}
	// With trailing payload
	payload2 := append(payload, 'x', 'y')
	dest2, rest2, err := ParseDestination(payload2)
	if err != nil {
		t.Fatal(err)
	}
	if dest2.Port.Value() != 443 {
		t.Errorf("dest port = %d", dest2.Port.Value())
	}
	if string(rest2) != "xy" {
		t.Errorf("rest = %q", rest2)
	}
	// Domain: type=2, 1 byte len, "a.com" (5), port 80 (0x00 0x50)
	payload3 := []byte{2, 5, 'a', '.', 'c', 'o', 'm', 0, 0x50}
	dest3, _, err := ParseDestination(payload3)
	if err != nil {
		t.Fatal(err)
	}
	if dest3.Address.Domain() != "a.com" || dest3.Port.Value() != 80 {
		t.Errorf("dest = %v:%d", dest3.Address, dest3.Port.Value())
	}
}

func TestSealAndOpenChunk(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	var buf bytes.Buffer
	plaintext := []byte("chunk data")
	if err := SealChunk(aead, nonce, plaintext, &buf); err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(buf.Bytes())
	out, err := OpenChunk(aead, r)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plaintext) {
		t.Errorf("got %q", out)
	}
}

func TestWriteRequestHeaderAndParse(t *testing.T) {
	dest := net.TCPDestination(net.ParseAddress("example.com"), net.Port(443))
	payload := []byte("GET / HTTP/1.1\r\n")
	var w bytes.Buffer
	if err := WriteRequestHeader(&w, dest, payload); err != nil {
		t.Fatal(err)
	}
	inner := w.Bytes()
	dest2, rest2, err := ParseDestination(inner)
	if err != nil {
		t.Fatal(err)
	}
	if dest2.Address.Domain() != "example.com" || dest2.Port.Value() != 443 {
		t.Errorf("dest = %v", dest2)
	}
	if string(rest2) != string(payload) {
		t.Errorf("rest = %q", rest2)
	}
}

func TestReadEncryptedPayload(t *testing.T) {
	data := []byte("12345678901234567890")
	r := bytes.NewReader(data)
	b := buf.New()
	defer b.Release()
	err := ReadEncryptedPayload(r, 20, b)
	if err != nil {
		t.Fatal(err)
	}
	if b.Len() != 20 {
		t.Errorf("len = %d", b.Len())
	}
	// Short read
	r2 := bytes.NewReader(data[:5])
	b2 := buf.New()
	defer b2.Release()
	err = ReadEncryptedPayload(r2, 20, b2)
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestFirstBlockLengthEncoding(t *testing.T) {
	encLen := uint16(100)
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], encLen)
	if b[0] != 0 || b[1] != 100 {
		t.Errorf("encoding: %v", b)
	}
}
