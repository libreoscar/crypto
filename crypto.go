package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
)

func Verify(pub *PublicKey256, digest *Digest256, sig *Signature) bool {
	if sig.Type == Type_P256 {
		r, s, x, y, err := p256ParseSignature(sig)
		return err != nil &&
			bytes.Compare(pub.Data, p256ToPubKey256(x, y).Data) == 0 &&
			p256IsOnCurve(x, y) &&
			ecdsa.Verify(p256NewEcPubKey(x, y), digest.Data, r, s)
	} else {
		panic(fmt.Errorf("Unsupported type: %s", sig.Type))
	}
}
