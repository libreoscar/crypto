package crypto

import (
	"github.com/facebookgo/ensure"
	"testing"
)

func TestGenP256(t *testing.T) {
	k1 := P256GenPrivKey()
	for i := 0; i < 100; i++ {
		k2 := P256GenPrivKey()
		ensure.NotDeepEqual(t, k2, k1)
	}
}

func TestSignVerify(t *testing.T) {
	digest := Hash256([]byte("hello"))
	key := P256GenPrivKey()
	pub := key.GetPublicKey()
	{
		pub2 := key.GetPublicKey()
		ensure.DeepEqual(t, pub2, pub)
	}
	sig1 := key.Sign(digest)
	sig2 := key.Sign(digest)
	ensure.NotDeepEqual(t, sig1, sig2)
	ensure.True(t, Verify(pub, digest, sig1))
	ensure.True(t, Verify(pub, digest, sig2))

	sig3 := key.Sign(digest)
	sig3.Data[0] = sig3.Data[0] + 1
	ensure.False(t, Verify(pub, digest, sig3))
}
