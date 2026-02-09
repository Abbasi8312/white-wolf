package whitewolf

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

// Client is the whitewolf outbound handler.
type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
}

// NewClient creates a new whitewolf outbound client.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config.Server == nil {
		return nil, errors.New("whitewolf: no server specified")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("whitewolf: failed to get server spec").Base(err)
	}
	v := core.MustFromContext(ctx)
	return &Client{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

// Process implements proxy.Outbound.Process.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("whitewolf: target not specified")
	}
	ob.Name = "whitewolf"
	destination := ob.Target

	server := c.server
	account, ok := server.User.Account.(*MemoryAccount)
	if !ok || account == nil {
		return errors.New("whitewolf: invalid account")
	}
	key := account.SymmetricKey
	if len(key) != KeySize {
		return errors.New("whitewolf: symmetric_key must be ", KeySize, " bytes")
	}
	block := common.Must2(aes.NewCipher(key))
	aead := common.Must2(cipher.NewGCM(block))

	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, server.Destination)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return errors.New("whitewolf: failed to dial server").Base(err)
	}
	defer conn.Close()

	sessionPolicy := c.policyManager.ForLevel(server.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	var firstPayload []byte
	if tr, ok := link.Reader.(buf.TimeoutReader); ok {
		firstMB, err := tr.ReadMultiBufferTimeout(100 * time.Millisecond)
		if err == nil && !firstMB.IsEmpty() {
			for _, b := range firstMB {
				firstPayload = append(firstPayload, b.Bytes()...)
			}
			buf.ReleaseMulti(firstMB)
		}
	} else {
		firstMB, err := link.Reader.ReadMultiBuffer()
		if err == nil && !firstMB.IsEmpty() {
			for _, b := range firstMB {
				firstPayload = append(firstPayload, b.Bytes()...)
			}
			buf.ReleaseMulti(firstMB)
		}
	}

	inner := buf.New()
	defer inner.Release()
	if err := WriteRequestHeader(inner, destination, firstPayload); err != nil {
		return err
	}
	plaintext := inner.Bytes()

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	blob := append(nonce, ciphertext...)
	if len(blob) > 0xFFFF {
		return errors.New("whitewolf: first block too large")
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(blob)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := conn.Write(blob); err != nil {
		return err
	}

	clientReader := &decryptReader{conn: conn, aead: aead}
	clientWriter := &encryptWriter{conn: conn, aead: aead}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, clientWriter, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(clientReader, link.Writer, buf.UpdateActivity(timer))
	}
	responseDonePost := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDonePost); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return err
	}
	return nil
}
