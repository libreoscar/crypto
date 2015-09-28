package crypto

import (
	"fmt"
	"math/big"
)

// precondition: n != nil
func isU256(n *big.Int) bool {
	return n.Sign() > -1 && n.BitLen() <= 256
}

// precondition: isU256(n) == true
func nonNegBigTo32Bytes(n *big.Int) []byte {
	if !isU256(n) {
		panic(fmt.Sprintf("n is not an u256: %x", n))
	}

	bytes := n.Bytes()
	ret := make([]byte, 32-len(bytes), 32)
	return append(ret, bytes...)
}
