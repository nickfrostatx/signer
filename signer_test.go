package signer_test

import (
	"github.com/nickfrostatx/signer"
	"testing"
)

func TestSampleSign(t *testing.T) {
	s := signer.New([]byte("abc"))
	expected := "token.Ocg-BUkXy0jeFpaqL9RDcci19nLySXmCQaniTHz4los"
	signed := s.Sign("token")
	if signed != expected {
		t.Error("Expected ", expected, "got", signed)
	}
}

func TestUnsignGood(t *testing.T) {
	s := signer.New([]byte("abc"))
	signed := "token.Ocg-BUkXy0jeFpaqL9RDcci19nLySXmCQaniTHz4los"
	unsigned, err := s.Unsign(signed)
	if err != nil {
		t.Error(err)
	} else if unsigned != "token" {
		t.Error("Expected \"token\" got", unsigned)
	}
}


func TestUnsignMissingSep(t *testing.T) {
	s := signer.New([]byte("abc"))
	_, err := s.Unsign("token")
	if err != signer.ErrBadSignature {
		t.Error("Expected ErrBadSignature, got", err)
	}
}

func TestUnsignBadEncoding(t *testing.T) {
	s := signer.New([]byte("abc"))
	signed := "token.$$$"
	_, err := s.Unsign(signed)
	if err == nil || err == signer.ErrBadSignature {
		t.Error("Expected CorruptInputError, got", err)
	}
}

func TestUnsignBadSignature(t *testing.T) {
	s := signer.New([]byte("abc"))
	signed := "token.This_is_not_the_base64-encoded_signature"
	_, err := s.Unsign(signed)
	if err != signer.ErrBadSignature {
		t.Error("Expected ErrBadSignature, got", err)
	}
}
