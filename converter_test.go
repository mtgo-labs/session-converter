package tgconv

import (
	"crypto/rand"
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
