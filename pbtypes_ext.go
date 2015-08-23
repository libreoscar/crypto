// TODO: copyright
// Delete this file if we implement a Digest() function for all necessary types

package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/golang/protobuf/proto"
)

//--------------------------- PublicKey256 --------------------------------------------------------

func (pubkey *PublicKey256) AsMapKey() string {
	return string(pubkey.Data)
}

func (pubkey *PublicKey256) ToText() string {
	return hex.EncodeToString(pubkey.Data)
}

func (pubkey *PublicKey256) IsValid() bool {
	return VerifyPublicKey(pubkey)
}

func TextToPublicKey(text string) (pubkey *PublicKey256, err error) {
	bytes, err := hex.DecodeString(text)
	if err != nil {
		return
	}

	pubkey = &PublicKey256{bytes}
	if !pubkey.IsValid() {
		err = fmt.Errorf("Invalid public key: %v", text)
		pubkey = nil
	}
	return
}

//--------------------------- KeyPair256 ----------------------------------------------------------

func (keypair *KeyPair256) ToText() string {
	bytes, err := proto.Marshal(keypair)
	if err != nil {
		panic(err) // pb type should be able to be marshaled
	}
	return hex.EncodeToString(bytes)
}

// The returned keypair is not validated, because it won't be transfered to others
func TextToKeyPair(text string) (*KeyPair256, error) {
	var (
		err     error
		keypair = new(KeyPair256)
	)

	bytes, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}

	err = proto.Unmarshal(bytes, keypair)
	if err != nil {
		return nil, err
	} else {
		return keypair, nil
	}
}

//--------------------------- Signature256 --------------------------------------------------------

func (signature *Signature256) AsMapKey() string {
	return string(signature.Data)
}

func (signature *Signature256) ToText() string {
	return hex.EncodeToString(signature.Data)
}

func (signature *Signature256) IsValid() bool {
	return len(signature.Data) == 256/8*2
}

func TextToSignature(text string) (sig *Signature256, err error) {
	bytes, err := hex.DecodeString(text)
	if err != nil {
		return
	}

	sig = &Signature256{bytes}
	if !sig.IsValid() {
		err = fmt.Errorf("Invalid signature: %v", text)
		sig = nil
	}
	return
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

func (digest *Digest256) Brief() string {
	return hex.EncodeToString(digest.Data[:2])
}

func (digest *Digest256) IsValid() bool {
	return len(digest.Data) == 256/8
}

func TextToDigest(text string) (digest *Digest256, err error) {
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

func NewDigest(bytes []byte) (digest *Digest256, err error) {
	cp := make([]byte, len(bytes))
	copy(cp, bytes)
	digest = &Digest256{cp}
	if !digest.IsValid() {
		err = fmt.Errorf("Invalid digest: %v", bytes)
		digest = nil
	}
	return
}
