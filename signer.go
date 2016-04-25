package signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"
	"strings"
)

const (
	salt = "sso-signer"
	sep  = "."
)

var (
	encoding        = base64.RawURLEncoding
	ErrBadSignature = errors.New("Bad signature")
	defaultHash     = sha256.New
)

type Signer struct {
	key []byte
	hashMethod func() hash.Hash
}

func New(key []byte) *Signer {
	return &Signer{
		key: key,
		hashMethod: defaultHash,
	}
}

func (s *Signer) deriveKey() []byte {
	h := s.hashMethod()
	h.Write([]byte(salt))
	h.Write(s.key)
	return h.Sum(nil)
}

func (s *Signer) getSignature(data string) []byte {
	derived := s.deriveKey()
	mac := hmac.New(s.hashMethod, derived)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func (s *Signer) Sign(data string) string {
	sig := s.getSignature(data)
	return data + sep + encoding.EncodeToString(sig)
}

func (s *Signer) Unsign(data string) (string, error) {
	parts := strings.SplitN(data, sep, 2)
	if len(parts) != 2 {
		return "", ErrBadSignature
	}
	sig, err := encoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	if !hmac.Equal(s.getSignature(parts[0]), sig) {
		return "", ErrBadSignature
	}
	return parts[0], nil
}
