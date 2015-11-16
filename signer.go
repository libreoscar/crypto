package crypto

import (
	"fmt"
)

// A very naive implementation.
// The interfaces are subject to change.

// TODO: make it safer & add useable features, e.g. protect by password, persistant starage,
// memory only, etc.
type Signer struct {
	keys       map[string]*PrivateKey // public key -> private key
	defaultKey *PublicKey256
}

func NewSigner() *Signer {
	return &Signer{make(map[string]*PrivateKey), nil}
}

func (s *Signer) AddKey(key *PrivateKey) {
	pubkey := key.GetPublicKey().AsMapKey()
	s.keys[pubkey] = key // key is used as immutable
}

func (s *Signer) AddDefaultKey(key *PrivateKey) {
	pubkey := key.GetPublicKey()
	s.keys[pubkey.AsMapKey()] = key
	s.defaultKey = pubkey
}

func (s *Signer) Size() int {
	return len(s.keys)
}

func (s *Signer) PublicKeys() []*PublicKey256 {
	rst := make([]*PublicKey256, 0, len(s.keys))
	for _, v := range s.keys {
		rst = append(rst, v.GetPublicKey())
	}
	return rst
}

func (s *Signer) Sign(pubkey *PublicKey256, digest *Digest256) (*Signature, error) {
	if pubkey == nil {
		return nil, fmt.Errorf("pubkey is nil")
	}
	if digest == nil {
		return nil, fmt.Errorf("digest is nil")
	}
	key := s.keys[pubkey.AsMapKey()]
	if key == nil {
		return nil, fmt.Errorf("can not find corresponding key")
	} else {
		return key.Sign(digest), nil
	}
}

func (s *Signer) DefaultSign(digest *Digest256) (*Signature, error) {
	return s.Sign(s.defaultKey, digest)
}
