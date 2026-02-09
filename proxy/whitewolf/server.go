package whitewolf

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	stdnet "net"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

// Server is the whitewolf inbound handler.
type Server struct {
	policyManager policy.Manager
	aead          cipher.AEAD
	fallbackDest  string
	fallbackType  string
}

// NewServer creates a new whitewolf inbound handler.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	key, err := config.Key()
	if err != nil {
		return nil, err
	}
	block := common.Must2(aes.NewCipher(key))
	aead := common.Must2(cipher.NewGCM(block))

	fbDest := config.GetFallbackDest()
	if fbDest == "" {
		return nil, errors.New("whitewolf: fallback_dest is required")
	}
	fbType := "tcp"
	if strings.HasPrefix(fbDest, "tcp:") {
		fbType = "tcp"
		fbDest = fbDest[4:]
	} else if strings.HasPrefix(fbDest, "unix:") {
		fbType = "unix"
		fbDest = fbDest[5:]
	}

	v := core.MustFromContext(ctx)
	return &Server{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		aead:          aead,
		fallbackDest:  fbDest,
		fallbackType:  fbType,
	}, nil
}

// Network implements proxy.Inbound.
func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

// Process implements proxy.Inbound.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := s.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	first := buf.NewWithSize(2 + 0xFFFF)
	encLen, err := ReadFirstBlock(conn, first)
	if err != nil {
		return errors.New("whitewolf: failed to read first block").Base(err)
	}

	if encLen > 0 {
		if _, err = first.ReadFullFrom(conn, int32(encLen)); err != nil {
			return errors.New("whitewolf: failed to read encrypted payload").Base(err)
		}
		ciphertext := first.BytesFrom(lengthBytes)
		plaintext, decErr := TryDecrypt(s.aead, ciphertext)
		if decErr == nil {
			dest, rest, parseErr := ParseDestination(plaintext)
			if parseErr == nil {
				first.Release()
				if err := conn.SetReadDeadline(time.Time{}); err != nil {
					return errors.New("unable to clear read deadline").Base(err).AtWarning()
				}
				return s.handleProxy(ctx, conn, rest, dest, dispatcher, sessionPolicy)
			}
		}
	}

	return s.passthrough(ctx, conn, first, dispatcher, sessionPolicy)
}

func (s *Server) handleProxy(ctx context.Context, conn stat.Connection, firstPayload []byte, destination net.Destination, dispatcher routing.Dispatcher, sessionPolicy policy.Session) error {
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return errors.New("whitewolf: failed to dispatch to ", destination).Base(err)
	}

	if len(firstPayload) > 0 {
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(firstPayload)}); err != nil {
			common.Must(common.Interrupt(link.Reader))
			common.Must(common.Interrupt(link.Writer))
			return err
		}
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     destination,
		Status: log.AccessAccepted,
		Reason: "",
	})
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "whitewolf"

	clientReader := &decryptReader{conn: conn, aead: s.aead}
	clientWriter := &encryptWriter{conn: conn, aead: s.aead}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(clientReader, link.Writer, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, clientWriter, buf.UpdateActivity(timer))
	}
	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("whitewolf: connection ends").Base(err)
	}
	return nil
}

type decryptReader struct {
	conn net.Conn
	aead cipher.AEAD
}

func (r *decryptReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	plaintext, err := OpenChunk(r.aead, r.conn)
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, err
	}
	b := buf.New()
	b.Write(plaintext)
	return buf.MultiBuffer{b}, nil
}

type encryptWriter struct {
	conn net.Conn
	aead cipher.AEAD
}

func (w *encryptWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	nonce := make([]byte, NonceSize)
	for _, b := range mb {
		if b.IsEmpty() {
			continue
		}
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		if err := SealChunk(w.aead, nonce, b.Bytes(), w.conn); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) passthrough(ctx context.Context, connection stat.Connection, first *buf.Buffer, dispatcher routing.Dispatcher, sessionPolicy policy.Session) error {
	defer first.Release()
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		errors.LogWarningInner(ctx, err, "unable to clear read deadline")
	}

	conn, err := stdnet.DialTimeout(s.fallbackType, s.fallbackDest, sessionPolicy.Timeouts.Handshake)
	if err != nil {
		return errors.New("whitewolf: failed to dial fallback ", s.fallbackDest).Base(err)
	}
	defer conn.Close()

	serverReader := buf.NewReader(conn)
	serverWriter := buf.NewWriter(conn)

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		if err := serverWriter.WriteMultiBuffer(buf.MultiBuffer{first}); err != nil {
			return err
		}
		return buf.Copy(buf.NewReader(connection), serverWriter, buf.UpdateActivity(timer))
	}
	clientWriter := buf.NewWriter(connection)
	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
	}
	if err := task.Run(ctx, task.OnSuccess(postRequest, task.Close(serverWriter)), task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		common.Must(common.Interrupt(serverReader))
		common.Must(common.Interrupt(serverWriter))
		return errors.New("whitewolf: passthrough ends").Base(err).AtInfo()
	}
	return nil
}
