package crypto

import (
	"github.com/facebookgo/ensure"
	"math/big"
	"testing"
)

func TestIsU256(t *testing.T) {
	ensure.True(t, isU256(big.NewInt(0)))
	ensure.True(t, isU256(big.NewInt(1)))
	ensure.False(t, isU256(big.NewInt(-1)))
	{
		buf := make([]byte, 64)
		n := new(big.Int).SetBytes(buf)
		ensure.True(t, isU256(n))
	}
	{
		buf := make([]byte, 64)
		for i := 0; i < 64; i++ {
			buf[i] = 255
		}
		n := new(big.Int).SetBytes(buf)
		ensure.False(t, isU256(n))
	}
	{
		buf := make([]byte, 32)
		for i := 0; i < 32; i++ {
			buf[i] = 255
		}
		n := new(big.Int).SetBytes(buf)
		ensure.True(t, isU256(n))
	}
}

func TestBigToBytes(t *testing.T) {
	{
		expected := make([]byte, 32)
		actual := nonNegBigTo32Bytes(big.NewInt(0))
		ensure.DeepEqual(t, actual, expected)
	}
	{
		expected := make([]byte, 32)
		expected[31] = 100
		actual := nonNegBigTo32Bytes(big.NewInt(100))
		ensure.DeepEqual(t, actual, expected)
	}
	{
		expected := make([]byte, 32)
		expected[31] = 4
		expected[30] = 1
		actual := nonNegBigTo32Bytes(big.NewInt(260))
		ensure.DeepEqual(t, actual, expected)
	}
	{
		expected := make([]byte, 32)
		for i := 0; i < 32; i++ {
			expected[i] = 255
		}
		one := big.NewInt(1)
		u256Max := new(big.Int).Sub(new(big.Int).Lsh(one, 256), one)
		actual := nonNegBigTo32Bytes(u256Max)
		ensure.DeepEqual(t, actual, expected)
	}
}
