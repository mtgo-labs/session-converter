package tgconv

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// EncodePyrogram encodes a session in Pyrogram string format.
//
// base64url(dc[1] + api_id[4 BE] + test_mode[1] + authkey[256] + user_id[8 BE] + is_bot[1])
// No version prefix. Total payload: 271 bytes.
func EncodePyrogram(s *Session) (string, error) {
	if err := s.validate(); err != nil {
		return "", err
	}

	buf := make([]byte, 0, 271)
	buf = append(buf, byte(s.DCID))

	appIDBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(appIDBuf, uint32(s.AppID))
	buf = append(buf, appIDBuf...)

	if s.TestMode {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	buf = append(buf, s.AuthKey...)

	uidBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(uidBuf, uint64(s.UserID))
	buf = append(buf, uidBuf...)

	if s.IsBot {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	encoded := base64.URLEncoding.EncodeToString(buf)
	return trimBase64Pad(encoded), nil
}

// DecodePyrogram decodes a Pyrogram session string.
//
// Supports the modern format (271 bytes) and legacy formats:
//   - 351 bytes: dc[1] + test_mode[1] + authkey[256] + user_id[4 BE] + is_bot[1]
//   - 356 bytes: dc[1] + test_mode[1] + authkey[256] + user_id[8 BE] + is_bot[1]
func DecodePyrogram(str string) (*Session, error) {
	payload, err := base64.URLEncoding.DecodeString(padBase64(str))
	if err != nil {
		return nil, fmt.Errorf("pyrogram: base64 decode: %w", err)
	}

	switch len(payload) {
	case 271:
		s, err := decodePyrogramModern(payload)
		if err != nil {
			return nil, err
		}
		s.fillDefaults()
		return s, nil
	case 351:
		s, err := decodePyrogramLegacy(payload, 4)
		if err != nil {
			return nil, err
		}
		s.fillDefaults()
		return s, nil
	case 356:
		s, err := decodePyrogramLegacy(payload, 8)
		if err != nil {
			return nil, err
		}
		s.fillDefaults()
		return s, nil
	default:
		return nil, fmt.Errorf("pyrogram: unexpected payload length %d (expected 271, 351, or 356)", len(payload))
	}
}

func decodePyrogramModern(p []byte) (*Session, error) {
	return &Session{
		DCID:    int(p[0]),
		AppID:   int32(binary.BigEndian.Uint32(p[1:5])),
		TestMode: p[5] != 0,
		AuthKey: bytesCopy(p[6:262]),
		UserID:  int64(binary.BigEndian.Uint64(p[262:270])),
		IsBot:   p[270] != 0,
	}, nil
}

// decodePyrogramLegacy decodes old-format Pyrogram sessions that omit api_id.
// uidSize is 4 (32-bit) or 8 (64-bit) user ID.
func decodePyrogramLegacy(p []byte, uidSize int) (*Session, error) {
	authKey := make([]byte, 256)
	copy(authKey, p[2:258])

	var userID int64
	if uidSize == 4 {
		userID = int64(int32(binary.BigEndian.Uint32(p[258:262])))
	} else {
		userID = int64(binary.BigEndian.Uint64(p[258:266]))
	}

	isBotOff := 258 + uidSize
	var isBot bool
	if isBotOff < len(p) {
		isBot = p[isBotOff] != 0
	}

	return &Session{
		DCID:     int(p[0]),
		TestMode: p[1] != 0,
		AuthKey:  authKey,
		UserID:   userID,
		IsBot:    isBot,
	}, nil
}

// bytesCopy returns a copy of b.
func bytesCopy(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// padBase64 adds padding to a base64 string.
func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// trimBase64Pad removes trailing = characters.
func trimBase64Pad(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}
