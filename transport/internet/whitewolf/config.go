package whitewolf

import (
	"context"
	"io"
	"net"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	reality_internet "github.com/xtls/xray-core/transport/internet/reality"
)

// GetREALITYConfig builds a reality.Config from whitewolf config with AcceptAll true,
// so the server accepts every client (no SessionId/shortId check).
func (c *Config) GetREALITYConfig() *reality.Config {
	var dialer net.Dialer
	config := &reality.Config{
		DialContext: dialer.DialContext,

		Show: c.Show,
		Type: c.Type,
		Dest: c.Dest,
		Xver: byte(c.Xver),

		PrivateKey:   c.PrivateKey,
		MinClientVer: c.MinClientVer,
		MaxClientVer: c.MaxClientVer,
		MaxTimeDiff:  time.Duration(c.MaxTimeDiff) * time.Millisecond,

		NextProtos:             nil,
		SessionTicketsDisabled: true,

		KeyLogWriter: KeyLogWriterFromConfig(c),

		AcceptAll: true,
	}
	if c.Mldsa65Seed != nil {
		_, key := mldsa65.NewKeyFromSeed((*[32]byte)(c.Mldsa65Seed))
		config.Mldsa65Key = key.Bytes()
	}
	if c.LimitFallbackUpload != nil {
		config.LimitFallbackUpload.AfterBytes = c.LimitFallbackUpload.AfterBytes
		config.LimitFallbackUpload.BytesPerSec = c.LimitFallbackUpload.BytesPerSec
		config.LimitFallbackUpload.BurstBytesPerSec = c.LimitFallbackUpload.BurstBytesPerSec
	}
	if c.LimitFallbackDownload != nil {
		config.LimitFallbackDownload.AfterBytes = c.LimitFallbackDownload.AfterBytes
		config.LimitFallbackDownload.BytesPerSec = c.LimitFallbackDownload.BytesPerSec
		config.LimitFallbackDownload.BurstBytesPerSec = c.LimitFallbackDownload.BurstBytesPerSec
	}
	config.ServerNames = make(map[string]bool)
	for _, serverName := range c.ServerNames {
		config.ServerNames[serverName] = true
	}
	config.ShortIds = make(map[[8]byte]bool)
	for _, shortId := range c.ShortIds {
		config.ShortIds[*(*[8]byte)(shortId)] = true
	}
	return config
}

func KeyLogWriterFromConfig(c *Config) io.Writer {
	if len(c.MasterKeyLog) <= 0 || c.MasterKeyLog == "none" {
		return nil
	}

	writer, err := os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to open ", c.MasterKeyLog, " as master key log")
	}

	return writer
}

func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}

// ConfigToReality converts whitewolf config to reality config (same structure).
// Used when dialing as a client so reality.UClient can perform the TLS handshake.
func ConfigToReality(w *Config) *reality_internet.Config {
	if w == nil {
		return nil
	}
	r := &reality_internet.Config{
		Show:          w.Show,
		Dest:          w.Dest,
		Type:          w.Type,
		Xver:          w.Xver,
		ServerNames:   w.ServerNames,
		PrivateKey:    w.PrivateKey,
		MinClientVer:  w.MinClientVer,
		MaxClientVer:  w.MaxClientVer,
		MaxTimeDiff:   w.MaxTimeDiff,
		ShortIds:      w.ShortIds,
		Mldsa65Seed:   w.Mldsa65Seed,
		Fingerprint:   w.Fingerprint,
		ServerName:    w.ServerName,
		PublicKey:     w.PublicKey,
		ShortId:       w.ShortId,
		Mldsa65Verify: w.Mldsa65Verify,
		SpiderX:       w.SpiderX,
		SpiderY:       w.SpiderY,
		MasterKeyLog:  w.MasterKeyLog,
	}
	if w.LimitFallbackUpload != nil {
		r.LimitFallbackUpload = &reality_internet.LimitFallback{
			AfterBytes:       w.LimitFallbackUpload.AfterBytes,
			BytesPerSec:      w.LimitFallbackUpload.BytesPerSec,
			BurstBytesPerSec: w.LimitFallbackUpload.BurstBytesPerSec,
		}
	}
	if w.LimitFallbackDownload != nil {
		r.LimitFallbackDownload = &reality_internet.LimitFallback{
			AfterBytes:       w.LimitFallbackDownload.AfterBytes,
			BytesPerSec:      w.LimitFallbackDownload.BytesPerSec,
			BurstBytesPerSec: w.LimitFallbackDownload.BurstBytesPerSec,
		}
	}
	return r
}

// ConfigFromReality converts a reality config to whitewolf config (same structure).
// Used when building from JSON whitewolfSettings that share the same shape as realitySettings.
func ConfigFromReality(r *reality_internet.Config) *Config {
	if r == nil {
		return nil
	}
	w := &Config{
		Show:          r.Show,
		Dest:          r.Dest,
		Type:          r.Type,
		Xver:          r.Xver,
		ServerNames:   r.ServerNames,
		PrivateKey:    r.PrivateKey,
		MinClientVer:  r.MinClientVer,
		MaxClientVer:  r.MaxClientVer,
		MaxTimeDiff:   r.MaxTimeDiff,
		ShortIds:      r.ShortIds,
		Mldsa65Seed:   r.Mldsa65Seed,
		Fingerprint:   r.Fingerprint,
		ServerName:    r.ServerName,
		PublicKey:     r.PublicKey,
		ShortId:       r.ShortId,
		Mldsa65Verify: r.Mldsa65Verify,
		SpiderX:       r.SpiderX,
		SpiderY:       r.SpiderY,
		MasterKeyLog:  r.MasterKeyLog,
	}
	if r.LimitFallbackUpload != nil {
		w.LimitFallbackUpload = &LimitFallback{
			AfterBytes:       r.LimitFallbackUpload.AfterBytes,
			BytesPerSec:      r.LimitFallbackUpload.BytesPerSec,
			BurstBytesPerSec: r.LimitFallbackUpload.BurstBytesPerSec,
		}
	}
	if r.LimitFallbackDownload != nil {
		w.LimitFallbackDownload = &LimitFallback{
			AfterBytes:       r.LimitFallbackDownload.AfterBytes,
			BytesPerSec:      r.LimitFallbackDownload.BytesPerSec,
			BurstBytesPerSec: r.LimitFallbackDownload.BurstBytesPerSec,
		}
	}
	return w
}
