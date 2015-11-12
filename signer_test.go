package crypto

import (
	"github.com/facebookgo/ensure"
	"testing"
)

func TestSigner(t *testing.T) {
	signer := NewSigner()
	key1 := P256GenPrivKey()
	key2 := P256GenPrivKey()

	signer.AddKey(key1)
	signer.AddKey(key1)

	ensure.DeepEqual(t, signer.Size(), 1)

	pubkeys := signer.PublicKeys()
	ensure.DeepEqual(t, len(pubkeys), 1)
	ensure.DeepEqual(t, pubkeys[0], key1.GetPublicKey())

	digest := Hash256([]byte("foo bar"))

	sig, err := signer.Sign(key1.GetPublicKey(), digest)
	ensure.Nil(t, err)
	ensure.True(t, Verify(key1.GetPublicKey(), digest, sig))

	sig, err = signer.Sign(key2.GetPublicKey(), digest)
	ensure.True(t, sig == nil)
	ensure.NotNil(t, err)
}
