package gateway

import (
	"bytes"
	"context"
	"testing"
)

// FuzzRelay checks the relay's core promise on arbitrary input: a line the gateway doesn't
// own is forwarded byte for byte. From the server, that is every line when no tools/list is
// pending. From the client, that is every line except a call to a decoy.
func FuzzRelay(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n",
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}` + "\n",
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_api_keys","arguments":{"x":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}` + "\n",
		`[{"method":"tools/call"}]`,
		"\x00\xff{",
		`{"id":null,"method":"tools/call","params":"x"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		g := &Gateway{Cfg: Config{CallbackURL: "http://127.0.0.1:1", Style: "catalog", Decoys: map[string]string{"list_api_keys": "t"},
			Salt: "fuzz-salt-0123456789", Fingerprints: []string{"00000000000000000000000000000000"}}}
		g.init()
		if out := g.fromServer(line); !bytes.Equal(out, line) {
			t.Fatalf("server line changed with nothing pending:\n%q\n%q", line, out)
		}
		var toServer, toClient bytes.Buffer
		if err := g.fromClient(context.Background(), line, &toClient, &toServer); err != nil {
			t.Fatal(err)
		}
		// No tools/list reply has been seen, so no decoy names exist yet: everything is relayed.
		if !bytes.Equal(toServer.Bytes(), line) || toClient.Len() != 0 {
			t.Fatalf("client line not relayed verbatim:\n%q\n%q", line, toServer.Bytes())
		}
		// Let any callback goroutine finish before the next input.
		g.wg.Wait()
	})
}
