// TODO: copyright
// The following use elliptic.P256 curve

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

var ( // DO NOT change their value
	curve   elliptic.Curve = elliptic.P256()
	byteLen int            = (curve.Params().BitSize + 7) >> 3
)

//------------------------------- Public functions -------------------------------------------------

func NewECKey256() (*KeyPair256, error) {
	priv_key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return fromECDSAPrivKey(priv_key), nil
}

func VerifyPublicKey(pubkey *PublicKey256) bool {
	return curve.IsOnCurve(unmarshalPublicKey(pubkey.Data))
}

func Sign(key_pair *KeyPair256, digest *Digest256) (sig *Signature256, err error) {
	r, s, err := ecdsa.Sign(rand.Reader, toECDSAPrivKey(key_pair), digest.Data)
	if err != nil {
		return
	} else {
		sig = &Signature256{marshalSignature(r, s)}
		return
	}
}

func Verify(pub *PublicKey256, digest *Digest256, sig *Signature256) bool {
	r, s := unmarshalSignature(sig.Data)
	return ecdsa.Verify(toECDSAPublicKey(pub), digest.Data, r, s)
}

//----------------------------- base functions -----------------------------------------------------

func marshalPrivKey(n *big.Int) []byte {
	ret := make([]byte, byteLen)
	nBytes := n.Bytes()
	copy(ret[byteLen-len(nBytes):], nBytes)
	return ret
}

func unmarshalPrivKey(data []byte) *big.Int {
	if len(data) != byteLen {
		return nil
	}
	return new(big.Int).SetBytes(data[:])
}

// TODO: use the compact form
func marshalPublicKey(x, y *big.Int) []byte { // 2 * byteLen + 1 bytes
	return elliptic.Marshal(curve, x, y)
}

// TODO: use the compact form
func unmarshalPublicKey(data []byte) (x, y *big.Int) {
	return elliptic.Unmarshal(curve, data)
}

// TODO: care about s > n - s?
func marshalSignature(r, s *big.Int) []byte { // 2 * byteLen bytes
	ret := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(ret[byteLen-len(rBytes):], rBytes)
	copy(ret[2*byteLen-len(sBytes):], sBytes)
	return ret
}

func unmarshalSignature(data []byte) (r, s *big.Int) {
	if len(data) != 2*byteLen {
		return
	}
	r = new(big.Int).SetBytes(data[:byteLen])
	s = new(big.Int).SetBytes(data[byteLen:])
	return
}

//------------------------------- More advanced helpers --------------------------------------------

func fromECDSAPublicKey(pubkey *ecdsa.PublicKey) *PublicKey256 {
	return &PublicKey256{marshalPublicKey(pubkey.X, pubkey.Y)}
}

func toECDSAPublicKey(pubkey *PublicKey256) *ecdsa.PublicKey {
	x, y := unmarshalPublicKey(pubkey.Data)
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
}

func fromECDSAPrivKey(privkey *ecdsa.PrivateKey) *KeyPair256 {
	return &KeyPair256{
		marshalPrivKey(privkey.D),
		fromECDSAPublicKey(&privkey.PublicKey),
	}
}

func toECDSAPrivKey(keypair *KeyPair256) *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: *toECDSAPublicKey(keypair.PublicKey),
		D:         unmarshalPrivKey(keypair.PrivKey),
	}
}
