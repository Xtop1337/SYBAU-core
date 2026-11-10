// utls-dump writes the ClientHello templates used by sybau-tls.
//
// For every fingerprint it asks uTLS (the library Xray uses) to build a
// real ClientHello and records its structure: cipher suites, compression
// methods and the ordered list of extensions with their bytes. The Rust
// side rebuilds hellos from these templates, replacing only the parts
// that must be fresh for every connection (randoms, key shares, GREASE
// values, SNI, padding).
//
//	go run . > ../../crates/sybau-tls/src/fingerprints.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

// SNI used while sampling; its length matters for the padding extension,
// which the Rust side recomputes.
const sampleSNI = "example.com"

type extension struct {
	ID   uint16 `json:"id"`
	Data string `json:"data"`
}

type template struct {
	Name          string      `json:"name"`
	UTLS          string      `json:"utls"`
	LegacyVersion uint16      `json:"legacy_version"`
	SessionIDLen  int         `json:"session_id_len"`
	CipherSuites  []uint16    `json:"cipher_suites"`
	Compression   []int       `json:"compression"`
	Extensions    []extension `json:"extensions"`
	Shuffle       bool        `json:"shuffle"`
	SupportsTLS13 bool        `json:"supports_tls13"`
	Sample        string      `json:"sample"`
}

func build(id utls.ClientHelloID) ([]byte, error) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn := utls.UClient(a, &utls.Config{ServerName: sampleSNI}, id)
	if err := conn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	return conn.HandshakeState.Hello.Raw, nil
}

func parse(raw []byte) (*template, error) {
	s := cryptobyte.String(raw)
	var msgType uint8
	var body cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != 1 || !s.ReadUint24LengthPrefixed(&body) {
		return nil, fmt.Errorf("not a ClientHello")
	}
	t := &template{Sample: hex.EncodeToString(raw)}
	var random []byte
	var sessionID, ciphers, compression, exts cryptobyte.String
	if !body.ReadUint16(&t.LegacyVersion) || !body.ReadBytes(&random, 32) ||
		!body.ReadUint8LengthPrefixed(&sessionID) || !body.ReadUint16LengthPrefixed(&ciphers) ||
		!body.ReadUint8LengthPrefixed(&compression) {
		return nil, fmt.Errorf("truncated ClientHello")
	}
	t.SessionIDLen = len(sessionID)
	for !ciphers.Empty() {
		var c uint16
		ciphers.ReadUint16(&c)
		t.CipherSuites = append(t.CipherSuites, c)
	}
	t.Compression = []int{}
	for _, c := range compression {
		t.Compression = append(t.Compression, int(c))
	}
	t.Extensions = []extension{}
	if !body.Empty() && !body.ReadUint16LengthPrefixed(&exts) {
		return nil, fmt.Errorf("truncated extensions")
	}
	for !exts.Empty() {
		var id uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, fmt.Errorf("truncated extension")
		}
		t.Extensions = append(t.Extensions, extension{ID: id, Data: hex.EncodeToString(data)})
		if id == 43 {
			versions := cryptobyte.String(data)
			var list cryptobyte.String
			versions.ReadUint8LengthPrefixed(&list)
			for !list.Empty() {
				var v uint16
				list.ReadUint16(&v)
				if v == 0x0304 {
					t.SupportsTLS13 = true
				}
			}
		}
	}
	return t, nil
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// order returns the extension IDs with GREASE values (which differ
// between samples) replaced by a constant.
func order(t *template) []uint16 {
	ids := make([]uint16, len(t.Extensions))
	for i, e := range t.Extensions {
		ids[i] = e.ID
		if isGREASE(e.ID) {
			ids[i] = 0x0a0a
		}
	}
	return ids
}

func main() {
	// Presets exposed in the config, as Xray maps them, followed by the
	// pool that `random` picks from.
	fingerprints := []struct {
		name string
		id   utls.ClientHelloID
	}{
		{"chrome", utls.HelloChrome_Auto},
		{"firefox", utls.HelloFirefox_Auto},
		{"safari", utls.HelloSafari_Auto},
		{"ios", utls.HelloIOS_Auto},
		{"android", utls.HelloAndroid_11_OkHttp},
		{"edge", utls.HelloEdge_Auto},
		{"360", utls.Hello360_Auto},
		{"qq", utls.HelloQQ_Auto},
		{"firefox_99", utls.HelloFirefox_99},
		{"firefox_102", utls.HelloFirefox_102},
		{"firefox_105", utls.HelloFirefox_105},
		{"firefox_120", utls.HelloFirefox_120},
		{"chrome_83", utls.HelloChrome_83},
		{"chrome_87", utls.HelloChrome_87},
		{"chrome_96", utls.HelloChrome_96},
		{"chrome_100", utls.HelloChrome_100},
		{"chrome_102", utls.HelloChrome_102},
		{"chrome_106_shuffle", utls.HelloChrome_106_Shuffle},
		{"chrome_120", utls.HelloChrome_120},
		{"chrome_131", utls.HelloChrome_131},
		{"ios_13", utls.HelloIOS_13},
		{"edge_106", utls.HelloEdge_106},
		{"safari_16_0", utls.HelloSafari_16_0},
		{"360_11_0", utls.Hello360_11_0},
	}
	out := []*template{}
	for _, f := range fingerprints {
		raw, err := build(f.id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s (%s): %v\n", f.name, f.id.Str(), err)
			continue
		}
		t, err := parse(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", f.name, err)
			continue
		}
		t.Name = f.name
		t.UTLS = f.id.Str()
		// A fingerprint shuffles its extensions if two builds disagree.
		for i := 0; i < 8 && !t.Shuffle; i++ {
			raw2, err := build(f.id)
			if err != nil {
				break
			}
			if t2, err := parse(raw2); err == nil && !reflect.DeepEqual(order(t), order(t2)) {
				t.Shuffle = true
			}
		}
		out = append(out, t)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
