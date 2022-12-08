package vdf

import (
	"math/big"
)

type VDF struct {
	p *big.Int
	q *big.Int
	n *big.Int
}

func New(p, q *big.Int) *VDF {
	v := VDF{
		p: new(big.Int).Set(p),
		q: new(big.Int).Set(q),
	}

	n := big.NewInt(0).Set(p)
	n.Mul(n, q)
	v.n = n

	return &v
}

// Set x = x**(2**t) mod m and returns x
func (v *VDF) Pow2tMod(x *big.Int, t int, m *big.Int) *big.Int {
	for i := 0; i < t; i++ {
		x.Mul(x, x)
		x.Mod(x, m)
	}

	return x
}

var c2 *big.Int = big.NewInt(2)

func (v *VDF) Pow2tMod_2(x *big.Int, t int, m *big.Int) *big.Int {
	for i := 0; i < t; i++ {
		x.Exp(x, c2, m)
	}

	return x
}

// Eval a proof and set x = proof
func (v *VDF) Eval(x *big.Int, t int) *big.Int {
	return v.Pow2tMod(x, t, v.n)
}

func (v *VDF) Verify(x *big.Int, t int, y *big.Int) bool {
	// phi = (p - 1)(q - 1)
	p_1 := new(big.Int).Set(v.p)
	p_1.Sub(p_1, big.NewInt(1))
	q_1 := new(big.Int).Set(v.q)
	q_1.Sub(q_1, big.NewInt(1))

	phi := big.NewInt(1)
	phi.Mul(p_1, q_1)

	// r = (2^t) mod phi
	r := big.NewInt(0)

	r.Exp(big.NewInt(2), big.NewInt(int64(t)), phi)

	// y = (x^r) mod n

	real_y := big.NewInt(0).Exp(x, r, v.n)

	if y.Cmp(real_y) == 0 {
		return true
	} else {
		return false
	}
}
