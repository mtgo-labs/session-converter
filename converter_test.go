package tgconv

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// makeTestSession creates a session with deterministic fields for testing.
func makeTestSession() *Session {
	authKey := make([]byte, 256)
	for i := range authKey {
		authKey[i] = byte(i) // deterministic test key
	}
	return &Session{
		DCID:          2,
		ServerAddress: "149.154.167.51",
		Port:          443,
		AuthKey:       authKey,
		AppID:         2040,
		TestMode:      false,
		UserID:        123456789,
		IsBot:         true,
	}
}

// makeRandomSession creates a session with a random auth key.
func makeRandomSession() *Session {
	authKey := make([]byte, 256)
	rand.Read(authKey) //nolint:gosec // test helper
	return &Session{
		DCID:          4,
		ServerAddress: "149.154.167.91",
		Port:          443,
		AuthKey:       authKey,
		AppID:         611335,
		TestMode:      false,
		UserID:        9876543210,
		IsBot:         false,
	}
}

func TestRoundTripTelethon(t *testing.T) {
	s := makeTestSession()
	encoded, err := EncodeTelethon(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeTelethon(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertAuthKeyEqual(t, s.AuthKey, decoded.AuthKey)
	if s.DCID != decoded.DCID {
		t.Errorf("DCID: got %d, want %d", decoded.DCID, s.DCID)
	}
	if s.ServerAddress != decoded.ServerAddress {
		t.Errorf("ServerAddress: got %s, want %s", decoded.ServerAddress, s.ServerAddress)
	}
	if s.Port != decoded.Port {
		t.Errorf("Port: got %d, want %d", decoded.Port, s.Port)
	}
}

func TestRoundTripPyrogram(t *testing.T) {
	s := makeTestSession()
	encoded, err := EncodePyrogram(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodePyrogram(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)
	if s.DCID != decoded.DCID {
		t.Errorf("DCID: got %d, want %d", decoded.DCID, s.DCID)
	}
	if s.AppID != decoded.AppID {
		t.Errorf("AppID: got %d, want %d", decoded.AppID, s.AppID)
	}
	if s.UserID != decoded.UserID {
		t.Errorf("UserID: got %d, want %d", decoded.UserID, s.UserID)
	}
	if s.IsBot != decoded.IsBot {
		t.Errorf("IsBot: got %v, want %v", decoded.IsBot, s.IsBot)
	}
}

func TestRoundTripGramJS(t *testing.T) {
	s := makeTestSession()
	encoded, err := EncodeGramJS(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeGramJS(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)
	if s.DCID != decoded.DCID {
		t.Errorf("DCID: got %d, want %d", decoded.DCID, s.DCID)
	}
	if s.ServerAddress != decoded.ServerAddress {
		t.Errorf("ServerAddress: got %s, want %s", decoded.ServerAddress, s.ServerAddress)
	}
	if s.Port != decoded.Port {
		t.Errorf("Port: got %d, want %d", decoded.Port, s.Port)
	}
}

// TestGramJSBinaryIPv4 verifies decoding a GramJS string whose server address
// is stored as a 4-byte binary IPv4 (a variant some converters emit) yields a
// dotted-quad address rather than garbage. Standard GramJS uses a string IP,
// which is covered by TestRoundTripGramJS.
func TestGramJSBinaryIPv4(t *testing.T) {
	s := makeTestSession()
	authKey := s.AuthKey

	// Build: dc[1] + addrLen[2 BE]=4 + ipv4[4] + port[2 BE] + authkey[256].
	buf := make([]byte, 0, 1+2+4+2+256)
	buf = append(buf, byte(s.DCID))
	buf = append(buf, 0x00, 0x04) // addrLen = 4
	buf = append(buf, 149, 154, 167, 51) // DC2 IPv4 as binary
	buf = append(buf, byte(s.Port>>8), byte(s.Port)) // port, big-endian
	buf = append(buf, authKey...)

	encoded := "1" + base64.StdEncoding.EncodeToString(buf)

	decoded, err := DecodeGramJS(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ServerAddress != "149.154.167.51" {
		t.Errorf("ServerAddress: got %q, want 149.154.167.51", decoded.ServerAddress)
	}
	if decoded.Port != s.Port {
		t.Errorf("Port: got %d, want %d", decoded.Port, s.Port)
	}
	if decoded.DCID != s.DCID {
		t.Errorf("DCID: got %d, want %d", decoded.DCID, s.DCID)
	}
	assertAuthKeyEquals(t, authKey, decoded.AuthKey)

	// Auto-detect must still classify it as GramJS.
	if f := DetectFormat(encoded); f != FormatGramJS {
		t.Errorf("DetectFormat: got %s, want %s", f, FormatGramJS)
	}
}

func TestRoundTripMtcute(t *testing.T) {
	s := makeTestSession()
	encoded, err := EncodeMtcute(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeMtcute(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)
	if s.DCID != decoded.DCID {
		t.Errorf("DCID: got %d, want %d", decoded.DCID, s.DCID)
	}
	if s.UserID != decoded.UserID {
		t.Errorf("UserID: got %d, want %d", decoded.UserID, s.UserID)
	}
	if s.IsBot != decoded.IsBot {
		t.Errorf("IsBot: got %v, want %v", decoded.IsBot, s.IsBot)
	}
}

func TestRoundTripMTKruto(t *testing.T) {
	s := makeTestSession()
	encoded, err := EncodeMTKruto(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeMTKruto(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)
	if s.DCID != decoded.DCID {
		t.Errorf("DCID: got %d, want %d", decoded.DCID, s.DCID)
	}
	if s.AppID != decoded.AppID {
		t.Errorf("AppID: got %d, want %d", decoded.AppID, s.AppID)
	}
	if s.UserID != decoded.UserID {
		t.Errorf("UserID: got %d, want %d", decoded.UserID, s.UserID)
	}
	if s.IsBot != decoded.IsBot {
		t.Errorf("IsBot: got %v, want %v", decoded.IsBot, s.IsBot)
	}
}

func TestRoundTripGogram(t *testing.T) {
	s := makeTestSession()
	encoded, err := EncodeGogram(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeGogram(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)
	if s.DCID != decoded.DCID {
		t.Errorf("DCID: got %d, want %d", decoded.DCID, s.DCID)
	}
	if s.ServerAddress != decoded.ServerAddress {
		t.Errorf("ServerAddress: got %s, want %s", decoded.ServerAddress, s.ServerAddress)
	}
	if s.AppID != decoded.AppID {
		t.Errorf("AppID: got %d, want %d", decoded.AppID, s.AppID)
	}
}

func TestRoundTripGotgproto(t *testing.T) {
	s := makeTestSession()
	encoded, err := EncodeGotgproto(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeGotgproto(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)
	if s.DCID != decoded.DCID {
		t.Errorf("DCID: got %d, want %d", decoded.DCID, s.DCID)
	}
}

func TestCrossFormatConversion(t *testing.T) {
	original := makeRandomSession()

	// Encode in each format, decode, and verify auth key survives the round trip.
	for _, f := range AllFormats {
		encoded, err := Encode(original, f)
		if err != nil {
			t.Errorf("encode %s: %v", f, err)
			continue
		}
		decoded, err := decodeByFormat(encoded, f)
		if err != nil {
			t.Errorf("decode %s: %v", f, err)
			continue
		}
		if len(decoded.AuthKey) != 256 {
			t.Errorf("%s: auth key length %d", f, len(decoded.AuthKey))
			continue
		}
		assertAuthKeyEqualsMsg(t, original.AuthKey, decoded.AuthKey, string(f))
	}
}

func TestConvertChain(t *testing.T) {
	original := makeTestSession()

	// Telethon → Pyrogram → GramJS → Telethon: auth key must survive.
	telethonStr, _ := EncodeTelethon(original)

	pyrogramStr, err := Convert(telethonStr, FormatPyrogram)
	if err != nil {
		t.Fatalf("telethon→pyrogram: %v", err)
	}

	gramjsStr, err := Convert(pyrogramStr, FormatGramJS)
	if err != nil {
		t.Fatalf("pyrogram→gramjs: %v", err)
	}

	telethonStr2, err := Convert(gramjsStr, FormatTelethon)
	if err != nil {
		t.Fatalf("gramjs→telethon: %v", err)
	}

	decoded, err := DecodeTelethon(telethonStr2)
	if err != nil {
		t.Fatalf("final decode: %v", err)
	}
	assertAuthKeyEquals(t, original.AuthKey, decoded.AuthKey)
}

func TestConvertAllFormats(t *testing.T) {
	original := makeTestSession()
	telethonStr, _ := EncodeTelethon(original)

	for _, target := range AllFormats {
		output, err := Convert(telethonStr, target)
		if err != nil {
			t.Errorf("convert to %s: %v", target, err)
			continue
		}
		// Decode back and verify auth key.
		decoded, _, err := Decode(output)
		if err != nil {
			t.Errorf("decode %s output: %v", target, err)
			continue
		}
		assertAuthKeyEqualsMsg(t, original.AuthKey, decoded.AuthKey, "convert→"+string(target))
	}
}

func TestDetectFormat(t *testing.T) {
	s := makeTestSession()

	tests := []struct {
		format Format
		encode func(*Session) (string, error)
	}{
		{FormatTelethon, EncodeTelethon},
		{FormatPyrogram, EncodePyrogram},
		{FormatGramJS, EncodeGramJS},
		{FormatMtcute, EncodeMtcute},
		{FormatMTKruto, EncodeMTKruto},
		{FormatGogram, EncodeGogram},
		{FormatGotgproto, EncodeGotgproto},
	}

	for _, tt := range tests {
		encoded, err := tt.encode(s)
		if err != nil {
			t.Fatalf("encode %s: %v", tt.format, err)
		}
		detected := DetectFormat(encoded)
		if detected != tt.format {
			t.Errorf("detect %s: got %s", tt.format, detected)
		}
	}
}

func TestRLE(t *testing.T) {
	tests := []struct {
		input []byte
	}{
		{[]byte{1, 2, 3}},
		{[]byte{0, 0, 0, 1, 2}},
		{[]byte{1, 0, 0, 0, 0, 0, 2}},
		{make([]byte, 300)}, // all zeros, > 255
		{[]byte{}},
	}

	for _, tt := range tests {
		encoded := rleEncode(tt.input)
		decoded := rleDecode(encoded)
		if len(decoded) != len(tt.input) {
			t.Errorf("length mismatch: got %d, want %d", len(decoded), len(tt.input))
			continue
		}
		for i := range tt.input {
			if decoded[i] != tt.input[i] {
				t.Errorf("byte %d: got %d, want %d", i, decoded[i], tt.input[i])
				break
			}
		}
	}
}

func TestEmptySession(t *testing.T) {
	_, _, err := Decode("")
	if err == nil {
		t.Error("expected error for empty session")
	}
}

func TestInvalidAuthKey(t *testing.T) {
	s := &Session{DCID: 2, AuthKey: make([]byte, 100)}
	_, err := EncodeTelethon(s)
	if err == nil {
		t.Error("expected error for short auth key")
	}
}

// --- Interop tests: verify compatibility with real-world session formats ---

// TestTelethonAlwaysV1 verifies that EncodeTelethon always emits the v1 prefix
// ("1") and never embeds api_id in the wire format — matching real Telethon
// (sessions/string.py, CURRENT_VERSION = "1", struct ">B{}sH256s"). AppID
// therefore does not survive a Telethon round trip.
func TestTelethonAlwaysV1(t *testing.T) {
	s := makeTestSession() // AppID = 2040

	encoded, err := EncodeTelethon(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded[0] != '1' {
		t.Fatalf("expected prefix '1', got %q", string(encoded[0]))
	}

	decoded, err := DecodeTelethon(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)
	if decoded.AppID != 0 {
		t.Errorf("AppID: got %d, want 0 (api_id is not stored in Telethon strings)", decoded.AppID)
	}

	if f := DetectFormat(encoded); f != FormatTelethon {
		t.Errorf("DetectFormat: got %s, want %s", f, FormatTelethon)
	}

	autoDecoded, detectedFmt, err := Decode(encoded)
	if err != nil {
		t.Fatalf("auto-decode: %v", err)
	}
	if detectedFmt != FormatTelethon {
		t.Errorf("auto-detected: got %s, want %s", detectedFmt, FormatTelethon)
	}
	assertAuthKeyEquals(t, s.AuthKey, autoDecoded.AuthKey)
}

// TestTelethonLegacyV2Decode verifies the decoder still accepts the legacy
// "2"+api_id variant this library once emitted, even though the encoder now
// only produces the standard "1" form. Existing (non-standard) strings stay
// readable.
func TestTelethonLegacyV2Decode(t *testing.T) {
	s := makeTestSession() // ServerAddress 149.154.167.51, Port 443, AppID 2040

	// Legacy "2" form: dc[1] + ip[4] + port[2 BE] + api_id[4 BE] + authkey[256].
	buf := make([]byte, 0, 1+4+2+4+256)
	buf = append(buf, byte(s.DCID))
	buf = append(buf, 149, 154, 167, 51) // DC2 IPv4
	buf = append(buf, byte(s.Port>>8), byte(s.Port))
	apiIDBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(apiIDBuf, uint32(s.AppID))
	buf = append(buf, apiIDBuf...)
	buf = append(buf, s.AuthKey...)
	encoded := "2" + base64.URLEncoding.EncodeToString(buf)

	decoded, err := DecodeTelethon(encoded)
	if err != nil {
		t.Fatalf("decode legacy v2: %v", err)
	}
	if decoded.DCID != s.DCID {
		t.Errorf("DCID: got %d, want %d", decoded.DCID, s.DCID)
	}
	if decoded.ServerAddress != s.ServerAddress {
		t.Errorf("ServerAddress: got %s, want %s", decoded.ServerAddress, s.ServerAddress)
	}
	if decoded.Port != s.Port {
		t.Errorf("Port: got %d, want %d", decoded.Port, s.Port)
	}
	if decoded.AppID != s.AppID {
		t.Errorf("AppID: got %d, want %d", decoded.AppID, s.AppID)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)

	if f := DetectFormat(encoded); f != FormatTelethon {
		t.Errorf("DetectFormat: got %s, want %s", f, FormatTelethon)
	}
	if _, fmt, err := Decode(encoded); err != nil || fmt != FormatTelethon {
		t.Errorf("Decode auto-detect: fmt=%s err=%v", fmt, err)
	}
}

// TestTelethonV1Prefix verifies that encoding without AppID produces v1.
func TestTelethonV1Prefix(t *testing.T) {
	s := makeTestSession()
	s.AppID = 0
	encoded, err := EncodeTelethon(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded[0] != '1' {
		t.Fatalf("expected prefix '1' for v1 (AppID=0), got %q", string(encoded[0]))
	}
	decoded, err := DecodeTelethon(encoded)
	if err != nil {
		t.Fatalf("decode v1: %v", err)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)
	if decoded.AppID != 0 {
		t.Errorf("AppID: got %d, want 0", decoded.AppID)
	}
}

// TestMtcuteDCVersion verifies the encoded DC option uses version 2
// (matching real mtcute and mtgo).
func TestMtcuteDCVersion(t *testing.T) {
	s := makeTestSession()
	encoded, err := EncodeMtcute(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	// Skip version (1B) + flags (4B), then read DC option TL bytes.
	off := 5
	dcData, _, err := readTLBytes(payload, off)
	if err != nil {
		t.Fatalf("read DC option: %v", err)
	}
	if len(dcData) < 1 {
		t.Fatalf("DC option too short")
	}
	if dcData[0] != 2 {
		t.Errorf("DC option version: got %d, want 2", dcData[0])
	}
}

// TestGotgprotoRawJSONData verifies the encoded outer Data field is raw
// JSON (not a double-base64-encoded string). Real gotgproto stores Data
// as a nested JSON object, not a base64 string.
func TestGotgprotoRawJSONData(t *testing.T) {
	s := makeTestSession()
	encoded, err := EncodeGotgproto(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	var outer map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}

	dataRaw, ok := outer["Data"]
	if !ok {
		t.Fatal("missing Data field")
	}

	// Data must NOT be a string — it should be a JSON object.
	var asStr string
	if err := json.Unmarshal(dataRaw, &asStr); err == nil {
		t.Fatalf("Data is a base64 string (double-encoded), expected raw JSON object")
	}

	// Data must parse as a JSON object with a Data envelope.
	var innerWrapper map[string]json.RawMessage
	if err := json.Unmarshal(dataRaw, &innerWrapper); err != nil {
		t.Fatalf("Data is not a JSON object: %v", err)
	}
	if _, ok := innerWrapper["Data"]; !ok {
		t.Fatal("inner Data envelope missing")
	}

	// Round-trip must still work.
	decoded, err := DecodeGotgproto(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertAuthKeyEquals(t, s.AuthKey, decoded.AuthKey)
}

// TestTelethonV1Compat decodes a real Telethon v1 string (no api_id,
// prefix "1") and verifies fields.
func TestTelethonV1Compat(t *testing.T) {
	// Build a Telethon v1 string manually: "1" + base64url(dc + ipv4 + port + authkey)
	s := makeTestSession()
	s.AppID = 0 // v1 has no api_id
	encoded, err := EncodeTelethon(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Must be v1 (prefix "1", no api_id).
	if encoded[0] != '1' {
		t.Fatalf("expected prefix '1', got %q", string(encoded[0]))
	}

	payload, err := base64.URLEncoding.DecodeString(encoded[1:])
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	// v1 IPv4: dc(1) + ip(4) + port(2) + authkey(256) = 263 bytes.
	if len(payload) != 263 {
		t.Errorf("v1 payload: got %d bytes, want 263", len(payload))
	}
}

// TestCrossFormatFromTelethon verifies that a Telethon string (built from a
// session carrying AppID) converts to every other format with the auth key
// preserved.
func TestCrossFormatFromTelethon(t *testing.T) {
	s := makeTestSession()
	telethonStr, err := EncodeTelethon(s)
	if err != nil {
		t.Fatalf("encode telethon: %v", err)
	}
	if telethonStr[0] != '1' {
		t.Fatalf("expected prefix '1', got %q", string(telethonStr[0]))
	}

	for _, target := range AllFormats {
		output, err := Convert(telethonStr, target)
		if err != nil {
			t.Errorf("convert telethon→%s: %v", target, err)
			continue
		}
		decoded, _, err := Decode(output)
		if err != nil {
			t.Errorf("decode %s: %v", target, err)
			continue
		}
		assertAuthKeyEqualsMsg(t, s.AuthKey, decoded.AuthKey, "telethon→"+string(target))
	}
}

// assertAuthKeyEquals checks that two auth keys are identical.
func assertAuthKeyEquals(t *testing.T, want, got []byte) {
	t.Helper()
	assertAuthKeyEqualsMsg(t, want, got, "")
}

func assertAuthKeyEqualsMsg(t *testing.T, want, got []byte, label string) {
	t.Helper()
	if len(want) != len(got) {
		t.Errorf("%s: auth key length: got %d, want %d", label, len(got), len(want))
		return
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("%s: auth key byte %d: got %d, want %d", label, i, got[i], want[i])
			return
		}
	}
}

// assertAuthKeyEqual is an alias for compatibility.
func assertAuthKeyEqual(t *testing.T, want, got []byte) {
	t.Helper()
	assertAuthKeyEqualsMsg(t, want, got, "")
}
