package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/token"
)

// Relay overhead (docs/M6-gateway.md, exit criterion): one tools/call round trip through an
// in-process pipe to an echo server, directly and through the gateway. The gateway case
// scans the call's arguments against fingerprints for 500 tripwires.

const benchArgs = 1 << 10

func echoServer(in io.Reader, out io.WriteCloser) {
	defer out.Close()
	br := bufio.NewReader(in)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(line, &m)
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"content": []any{}}})
		_, _ = out.Write(append(b, '\n'))
	}
}

func callLine() []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@example.com","body":"` +
		strings.Repeat("lorem ipsum ", benchArgs/12) + `"}}}` + "\n")
}

func roundTrips(b *testing.B, w io.Writer, r *bufio.Reader) {
	line := callLine()
	b.SetBytes(int64(len(line)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(line); err != nil {
			b.Fatal(err)
		}
		if _, err := r.ReadBytes('\n'); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundTripDirect(b *testing.B) {
	sIn, toSrv := io.Pipe()
	fromSrv, sOut := io.Pipe()
	go echoServer(sIn, sOut)
	defer toSrv.Close()
	roundTrips(b, toSrv, bufio.NewReader(fromSrv))
}

func BenchmarkRoundTripGateway(b *testing.B) { benchGateway(b, nil) }

// With containment on, a real call is scanned before it is forwarded (M8).
func BenchmarkRoundTripGatewayContain(b *testing.B) {
	benchGateway(b, &Contain{StateFile: filepath.Join(b.TempDir(), "frozen")})
}

func benchGateway(b *testing.B, contain *Contain) {
	s, _ := token.NewSigner(bytes.Repeat([]byte{1}, 32))
	const salt = "bench-salt-0123456789"
	var fps []string
	for i := 0; i < 500; i++ {
		_, id, _ := s.Mint()
		bodies, _ := s.Bodies(id)
		for _, body := range bodies {
			fps = append(fps, token.Fingerprint(salt, body))
		}
	}
	cIn, toGW := io.Pipe()
	fromGW, cOut := io.Pipe()
	sIn, toSrv := io.Pipe()
	fromSrv, sOut := io.Pipe()
	go echoServer(sIn, sOut)
	g := &Gateway{Cfg: Config{CallbackURL: "http://127.0.0.1:1", Style: "catalog", Salt: salt, Fingerprints: fps, Contain: contain}}
	go func() { _ = g.Run(context.Background(), cIn, cOut, toSrv, fromSrv) }()
	defer toGW.Close()
	roundTrips(b, toGW, bufio.NewReader(fromGW))
}
