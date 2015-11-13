//go:generate protoc -I $GOPATH/src --go_out=$GOPATH/src $GOPATH/src/github.com/libreoscar/crypto/crypto.proto

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

//--------------------------- PublicKey256 --------------------------------------------------------

func (pubkey *PublicKey256) AsMapKey() string {
	return string(pubkey.Data)
}

func (pubkey *PublicKey256) ToText() string {
	return hex.EncodeToString(pubkey.Data)
}

func Text2PublicKey256(text string) (*PublicKey256, error) {
	if len(text) != 256/8 {
		return nil, fmt.Errorf("invalid input")
	} else {
		bytes, err := hex.DecodeString(text)
		if err != nil {
			return nil, err
		}
		return &PublicKey256{bytes}, nil
	}
}

func (pubkey *PublicKey256) DebugString() string {
	return pubkey.ToText()
}

//--------------------------- PrivateKey ----------------------------------------------------------

func (key *PrivateKey) GetPublicKey() *PublicKey256 {
	if key.Type == Type_P256 {
		ecPriv := p256NewEcPrivKey(key.Data)
		return p256ToPubKey256(ecPriv.X, ecPriv.Y)
	} else {
		panic(fmt.Errorf("Unsupported type: %s", key.Type))
	}
}

func (key *PrivateKey) Sign(digest *Digest256) *Signature {
	if key.Type == Type_P256 {
		ecPriv := p256NewEcPrivKey(key.Data)
		r, s, err := ecdsa.Sign(rand.Reader, ecPriv, digest.Data)
		if err == nil {
			return p256ToSignature(ecPriv.X, ecPriv.Y, r, s)
		} else {
			panic(err)
		}
	} else {
		panic(fmt.Errorf("Unsupported type: %s", key.Type))
	}
}

func (key *PrivateKey) DebugString() string {
	return fmt.Sprintf("Type: %s, Data: %s", key.Type, hex.EncodeToString(key.Data[:8]))
}

func (key *PrivateKey) ToText() string {
	data, err := proto.Marshal(key)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
}

func Text2PrivateKey(text string) (*PrivateKey, error) {
	bytes, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}

	privKey := &PrivateKey{}
	err = proto.Unmarshal(bytes, privKey)
	if err != nil {
		return nil, err
	} else {
		return privKey, nil
	}
}

//--------------------------- Signature256 --------------------------------------------------------

func (s *Signature) DebugString() string {
	return fmt.Sprintf("Type: %s, Data: %s", s.Type, hex.EncodeToString(s.Data[:8]))
}

//--------------------------- Digest256 --------------------------------------------------------

func (digest *Digest256) EqualTo(d *Digest256) bool {
	return bytes.Equal(digest.Data, d.Data)
}

func (digest *Digest256) AsMapKey() string {
	return string(digest.Data)
}

func (digest *Digest256) ToText() string {
	return hex.EncodeToString(digest.Data)
}

func (digest *Digest256) IsValid() bool {
	return len(digest.Data) == 256/8
}

func TextToDigest256(text string) (digest *Digest256, err error) {
	bytes, err := hex.DecodeString(text)
	if err != nil {
		return
	}

	digest = &Digest256{bytes}
	if !digest.IsValid() {
		err = fmt.Errorf("Invalid digest: %v", text)
		digest = nil
	}
	return
}

func NewDigest256(bytes []byte) (digest *Digest256, err error) {
	cp := make([]byte, len(bytes))
	copy(cp, bytes)
	digest = &Digest256{cp}
	if !digest.IsValid() {
		err = fmt.Errorf("Invalid digest: %v", bytes)
		digest = nil
	}
	return
}

func (digest *Digest256) DebugString() string {
	return hex.EncodeToString(digest.Data[:2]) + "..."
}
