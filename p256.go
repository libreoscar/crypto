// TODO: copyright
// The following use elliptic.P256 curve

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

var ( // DO NOT change their value
	curveP256 elliptic.Curve = elliptic.P256()
)

//------------------------------- Helpers ---------------------------------------------------------

// {data}: the secret (a random number)
func p256NewEcPrivKey(data []byte) *ecdsa.PrivateKey {
	if len(data) > 32 {
		panic(fmt.Errorf("invalid parameter: %x", data))
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curveP256
	priv.D = new(big.Int).SetBytes(data)
	if priv.D.Sign() == 0 {
		panic("invalid parameter: secret is 0")
	}
	priv.PublicKey.X, priv.PublicKey.Y = curveP256.ScalarBaseMult(data)
	return priv
}

func p256IsOnCurve(x, y *big.Int) bool {
	return curveP256.IsOnCurve(x, y)
}

// Note: no validation
func p256NewEcPubKey(x, y *big.Int) *ecdsa.PublicKey {
	pub := new(ecdsa.PublicKey)
	pub.Curve = curveP256
	pub.X = x
	pub.Y = y
	return pub
}

// note: no validation
func p256ToPubKey256(x, y *big.Int) *PublicKey256 {
	hasher := NewHasher256()
	hasher.Feed([]byte(Type_P256.String()))
	hasher.Feed(nonNegBigTo32Bytes(x))
	hasher.Feed(nonNegBigTo32Bytes(y))
	return &PublicKey256{hasher.Sum(nil).Data}
}

// note: no validation
func p256ToSignature(x, y, r, s *big.Int) *Signature {
	buf := make([]byte, 0, 32*4)
	buf = append(buf, nonNegBigTo32Bytes(r)...)
	buf = append(buf, nonNegBigTo32Bytes(s)...)
	buf = append(buf, nonNegBigTo32Bytes(x)...)
	buf = append(buf, nonNegBigTo32Bytes(y)...)
	return &Signature{Type_P256, buf}
}

func p256ParseSignature(sig *Signature) (r, s, x, y *big.Int, err error) {
	if sig == nil || len(sig.Data) != 32*4 || sig.Type != Type_P256 {
		err = fmt.Errorf("Invalid parameter")
		return
	} else {
		r = new(big.Int).SetBytes(sig.Data[0:32])
		s = new(big.Int).SetBytes(sig.Data[32 : 32*2])
		x = new(big.Int).SetBytes(sig.Data[32*2 : 32*3])
		y = new(big.Int).SetBytes(sig.Data[32*3 : 32*4])
		return
	}
}

func p256GenEcPrivKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(curveP256, rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func P256GenPrivKey() *PrivateKey {
	priv_key := p256GenEcPrivKey()
	return &PrivateKey{Type_P256, nonNegBigTo32Bytes(priv_key.D)}
}
