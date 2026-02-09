package tcp

import (
	"context"
	gotls "crypto/tls"
	"reflect"
	"strings"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/whitewolf"
)

// Listener is an internet.Listener that listens for TCP connections.
type Listener struct {
	listener           net.Listener
	tlsConfig          *gotls.Config
	realityConfig      *goreality.Config
	useWhitewolfServer bool
	authConfig         internet.ConnectionAuthenticator
	config             *Config
	addConn            internet.ConnHandler
}

// ListenTCP creates a new Listener based on configurations.
func ListenTCP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn: handler,
	}
	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = tcpSettings
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
		streamSettings.SocketSettings.AcceptProxyProtocol = l.config.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol
	}
	var listener net.Listener
	var err error
	if port == net.Port(0) { // unix
		if !address.Family().IsDomain() {
			return nil, errors.New("invalid unix listen: ", address).AtError()
		}
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen Unix Domain Socket on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening Unix Domain Socket on ", address)
	} else {
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP on ", address, ":", port)
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		errors.LogWarning(ctx, "accepting PROXY protocol")
	}

	l.listener = listener

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		l.tlsConfig = config.GetTLSConfig()
	}

	// Diagnostic: what the TCP hub actually received for security
	if streamSettings != nil {
		secType := streamSettings.SecurityType
		hasSec := streamSettings.SecuritySettings != nil
		secSettingsType := ""
		if hasSec {
			secSettingsType = reflect.TypeOf(streamSettings.SecuritySettings).String()
		}
		errors.LogInfo(ctx, "transport/internet/tcp: hub streamSettings SecurityType=", secType, " SecuritySettings!=nil=", hasSec, " SecuritySettings.type=", secSettingsType, " InboundTag=", streamSettings.InboundTag, " InboundIsWhitewolf=", streamSettings.InboundIsWhitewolf)
	}

	// When security is whitewolf, server must use whitewolf path (AcceptAll); prefer SecurityType check then type of SecuritySettings.
	if streamSettings != nil && streamSettings.SecuritySettings != nil && strings.Contains(strings.ToLower(streamSettings.SecurityType), "whitewolf") {
		var wc *whitewolf.Config
		if c, ok := streamSettings.SecuritySettings.(*whitewolf.Config); ok {
			wc = c
			errors.LogInfo(ctx, "transport/internet/tcp: branch A — SecurityType contains whitewolf, SecuritySettings is *whitewolf.Config -> useWhitewolfServer=true")
		} else if rc, ok := streamSettings.SecuritySettings.(*reality.Config); ok {
			wc = whitewolf.ConfigFromReality(rc)
			errors.LogInfo(ctx, "transport/internet/tcp: branch A — SecurityType contains whitewolf, SecuritySettings converted to whitewolf -> useWhitewolfServer=true")
		}
		if wc != nil {
			l.realityConfig = wc.GetREALITYConfig()
			l.useWhitewolfServer = true
			go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
		} else {
			errors.LogInfo(ctx, "transport/internet/tcp: branch A — SecurityType contains whitewolf but type assert failed for config, wc=nil")
		}
	}
	// If we have reality config but SecurityType was not recognized as whitewolf, still prefer whitewolf when SecuritySettings is *whitewolf.Config.
	if l.realityConfig == nil && streamSettings != nil && streamSettings.SecuritySettings != nil {
		if wc, ok := streamSettings.SecuritySettings.(*whitewolf.Config); ok {
			l.realityConfig = wc.GetREALITYConfig()
			l.useWhitewolfServer = true
			errors.LogInfo(ctx, "transport/internet/tcp: branch B — SecuritySettings is *whitewolf.Config -> useWhitewolfServer=true")
			go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
		}
	}
	if l.realityConfig == nil {
		if config := whitewolf.ConfigFromStreamSettings(streamSettings); config != nil {
			l.realityConfig = config.GetREALITYConfig()
			l.useWhitewolfServer = true
			errors.LogInfo(ctx, "transport/internet/tcp: branch C — whitewolf.ConfigFromStreamSettings returned config -> useWhitewolfServer=true")
			go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
		} else if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
			l.realityConfig = config.GetREALITYConfig()
			// If SecurityType says whitewolf, inbound proxy is whitewolf, or inbound tag contains "whitewolf", use whitewolf server (AcceptAll).
			useWhitewolf := streamSettings != nil && (strings.Contains(strings.ToLower(streamSettings.SecurityType), "whitewolf") || streamSettings.InboundIsWhitewolf || strings.Contains(strings.ToLower(streamSettings.InboundTag), "whitewolf"))
			errors.LogInfo(ctx, "transport/internet/tcp: branch D — ConfigFromStreamSettings; SecurityType=", streamSettings.SecurityType, " InboundTag=", streamSettings.InboundTag, " InboundIsWhitewolf=", streamSettings.InboundIsWhitewolf, " -> useWhitewolf=", useWhitewolf)
			if useWhitewolf {
				wc := whitewolf.ConfigFromReality(config)
				l.realityConfig = wc.GetREALITYConfig()
				l.useWhitewolfServer = true
				errors.LogInfo(ctx, "transport/internet/tcp: branch D — useWhitewolf true -> using AcceptAll server")
			} else {
				errors.LogInfo(ctx, "transport/internet/tcp: branch D — useWhitewolf false -> using TLS server (SessionId check)")
			}
			go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
		}
	}

	if l.useWhitewolfServer {
		errors.LogInfo(ctx, "transport/internet/tcp: listener final useWhitewolfServer=true")
	} else {
		errors.LogInfo(ctx, "transport/internet/tcp: listener final useWhitewolfServer=false hasRealityConfig=", l.realityConfig != nil)
	}

	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("invalid header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("invalid header settings.").Base(err).AtError()
		}
		l.authConfig = auth
	}

	go l.keepAccepting()
	return l, nil
}

func (v *Listener) keepAccepting() {
	for {
		conn, err := v.listener.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "failed to accepted raw connections")
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}
		go func() {
			if v.tlsConfig != nil {
				conn = tls.Server(conn, v.tlsConfig)
			} else if v.realityConfig != nil {
				if v.useWhitewolfServer {
					errors.LogInfo(context.Background(), "transport/internet/tcp: accept — using whitewolf.Server (AcceptAll) for ", conn.RemoteAddr())
					if conn, err = whitewolf.Server(conn, v.realityConfig); err != nil {
						errors.LogInfo(context.Background(), "transport/internet/tcp: whitewolf.Server error: ", err.Error())
						return
					}
				} else {
					errors.LogInfo(context.Background(), "transport/internet/tcp: accept — using TLS server (SessionId) for ", conn.RemoteAddr())
					if conn, err = reality.Server(conn, v.realityConfig); err != nil {
						errors.LogInfo(context.Background(), err.Error())
						return
					}
				}
			}
			if v.authConfig != nil {
				conn = v.authConfig.Server(conn)
			}
			v.addConn(stat.Connection(conn))
		}()
	}
}

// Addr implements internet.Listener.Addr.
func (v *Listener) Addr() net.Addr {
	return v.listener.Addr()
}

// Close implements internet.Listener.Close.
func (v *Listener) Close() error {
	return v.listener.Close()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenTCP))
}
