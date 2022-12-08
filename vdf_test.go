package vdf

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"math/big"
	"math/rand"
	"testing"
)

const (
	x1 = 11
	p1 = 7
	q1 = 23
	n1 = 161 // == p1 * q1
	t1 = 256
	y1 = 95

	rsa512 = `-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAvonmo3Il4d0v6eex
GFmjw51SDUr4f2jxDbMA+3vHo0OBmQnfd5ED45T1EfupgpkXmBm/FmqGKuFYBEkD
ocfgTwIDAQABAkA3FGQgwYGj7i3Inxp5oIgPpy2t/AsjwbFVNXbGO/z0+7En2JOR
hz0oKdllcgkC8k/dnVM1oo3DK2F/8Cd+Mf6hAiEA+KHOSO/L/1pmdXVCZBhTp39Q
/aO08fZJA3g7/i2LuLECIQDEL2HPZAtbKTaxdPoLm4xNMbnrxU1/ewWV8djzXoNo
/wIhAOCVV75uTLiFsdMbbjL3/mhoCoJxo3qEWwN1UcuQ3IqhAiALnWKFDL8/XmlG
iE5lcYgU6eS/+KZl7bqe7fqSLf5JsQIhAJIopG7Ok7bzf9ZWJoO2vTFVYZngNiL2
u9wpBpMAtX64
-----END PRIVATE KEY-----
`

	rsa1024 = `-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMsukOcAChF/PC1g
NJksZCtZFjT3Uh7VFOLimEQ/YLLUyRTOrnOsJyXgKdEgSlncFEi8VOzCjw8KQaIv
GEeC5f4CtTZlXnZ2ONdecmCQUO4sWdWGozuFM0Q212KAknJftfdByfDIW8ctOVKJ
Xqv2ymZoIkWLSc8fzEGN2WSWYW+/AgMBAAECgYEAiSo3kmrZYTSHGI7xE1L/kLAE
qN8qJjxtbDnS14f9rNyvnwdkiBx5FT2+nTpyVzWWz/+sSWWTFHE1G9s1Rdmdj2iu
/k4h8II9jDm9yIPXbHuF1xTPUzgnsEa+d80xQjg9kNi1Jxr+Lgy8UFO+naQW/v+0
qFUpdkJHlyT3KnwBkIECQQDk8A3F6Bjdifo33XvkOcIyfy4lgDZTTfCFHbZHpRSn
4UOeaJAI1xN/Hr9U2MWQdwwPMlbMw+gq41XljD4f/WD/AkEA4zMbzkEQof4mWzr9
vYZXNgL69qgEO0sNVMtP0XyLOsqw59BntUZsqo4EAd7pvvAeXn526CCQyK5JR/hx
bYUxQQJBALDPsWNysJmQ8Z3pwcBu10vWq5Ys4kgOPr8gRmIo3b4WnPmfufYJ3bXk
0lI+JL9BIiAueZkliI5vCy0A1g4wy5MCQEdAewLnItk6xDquOG9clzMoIh6CuLkD
o42pKUIQZfWtJWe90xhlmqSuXxFbIEEyOsP1s0K/G8jj57V7c88eC0ECQQDj5aWt
xdGZPrgmPk8uTZBryhIfQs9tJMfycRZjTc4nFPVnR7pubKwexcpCVyCqodMhHW4u
NmM0MCplvNeWzzjr
-----END PRIVATE KEY-----`
	rsa2048 = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC5YrE7xVVreX3q
YnzeZHMTfWPIjoqO3Kop9ZaCGTbtgaghoo3Auaks46fS17DsRFoIL8ZIbvMJzXfq
vcF85RtnYYS1oYc6GVWkL4KM/NzHCavuu0P+wJK14oWuHKj2XCx+vkY85ou37Z4w
JVGMd9GuZPlsoycM5h502Y/k9v1kVN64TmLiqG7/kTX9Sl5if9TmY6nY6D1E6EhD
T6BJCRGX+a9s3vCbARco8aMgk+b8IK+VS5zDv03JIDFuIg8kV5cw6RrMz60uAjAF
4sj+yE2fFW+0yiJIP7lWVwoP2Fm6ucqBddWo8jiDAfLFLrWy3WJ4H4JJbn1cM920
5fRwxaMPAgMBAAECggEAEZjxs/fGZP5SWoZgzgeA+O+lIiuNsYP2zybV06GrGh59
pDu28v1stqshih0ZWUQfu7k1PDjz7xFG+cxranyg/k4+d7NOj9BJ1d0AqntyRZ6A
aJf0G2GSS5umDuH/k+sp+hn7tto3lw0CQBW6yPeyurgxCQPvuAS8DWF9jEF5yiUu
yZnSeDV+lY04vFJNAmtT+kiO0KPvHTdE+3y+A4qTtJ8dvnHKOU6Sb9djclTFLKDH
lylFqna4I+qHAJMIUBLrfa7vZ6c9C3DZDzBg3NHVEfswxkHUSIaEC0UerztsgJq7
13eHmxOWcZUEswXL4dG3PZmrrLKAV43+ddST2HTb8QKBgQDqxK8x6peap53dxs4G
Pt2iQbKNx1uug74RCIZqlKqg7d5JcoClzj8/Hbi7sr1ewO50TuKX9BGOc5Xw/onB
Uhbbt7KUG8m9FTiSHwP9jvoXEMrxjmdFEzpGkadzcMZ6ovowuXiFpY4LS5KQSXFr
yaxa4biu5nGXo5azjTdd2SkniQKBgQDKJrTK6dQ4/zIrlTa0Cm9xP/kzuOEM9VQZ
Z7vwRXFb/6BCe5n5hdJGEH8tj9HcffHnVF21m0cXk6aGmBYGVnYU87OpmrvrdcCA
eja7a75/e6ONr8Orhfkz+xSoLadCor8hM2DQAkW0GjLsIa5FxT39XnsvI1x9RxsV
/47qVT831wKBgQCO+x7gPcn7bN5etbfAYgVFztFaO/KAhMf7Q7/ppYWN4ZEiFlR3
pvcqD4X0+tUOol4YA/tJJGKU6ZyGW9+2F7LIOkbOoWXqfMQpai5Z/PwflCCloV8P
2LgDRq4/Ro37HstVZYAblUq/YlVu/uvPA9Kuvw5lpv/DpOQhkn4H8Dx6UQKBgQCA
rXTF+WQax+8yqO/CWSYpK7TAhL3U1tEqvsp2Hm4TRrvHthAEMnfwG44o/XRz60Ox
ohVohagSTO1inarfa+gMXDiQDKv0LOdVoPX4BZSkZ5prlWdzZnuD6B51E2J120zY
oHDO17Nw+oBRqPra9LwJ7TtyfQrhwAJw1VUuuwbbzwKBgQCXCYxRoRtSXXHHnJko
6mFfQAj0LZrt51bNsO3v0ySro3mNwEBZ7mP77HqQ3wgM0eLnuOLBX+9ml20M6QMF
BzBJOtzNhA5fAx83FhouhU5PInvlSTaSwo7Si7XT2/GCQP8gUfjc+G12SgESsua7
tU4k48ZvKvNR1R0GkKJWidPCbw==
-----END PRIVATE KEY-----`
	rsa4096 = `-----BEGIN PRIVATE KEY-----
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
0tksjZZz6djY+ZTHXSdQSNrcl9A4
-----END PRIVATE KEY-----`
)

var p512, q512 *big.Int
var p1024, q1024 *big.Int
var p2048, q2048 *big.Int
var p4096, q4096 *big.Int

func init() {
	b512, _ := pem.Decode([]byte(rsa512))
	pkey512_any, err := x509.ParsePKCS8PrivateKey(b512.Bytes)
	if err != nil {
		panic(err)
	}

	pkey512 := pkey512_any.(*rsa.PrivateKey)
	p512 = pkey512.Primes[0]
	q512 = pkey512.Primes[1]

	b1024, _ := pem.Decode([]byte(rsa1024))
	pkey1024_any, err := x509.ParsePKCS8PrivateKey(b1024.Bytes)
	if err != nil {
		panic(err)
	}

	pkey1024 := pkey1024_any.(*rsa.PrivateKey)
	p1024 = pkey1024.Primes[0]
	q1024 = pkey1024.Primes[1]

	b2048, _ := pem.Decode([]byte(rsa2048))
	pkey2048_any, err := x509.ParsePKCS8PrivateKey(b2048.Bytes)
	if err != nil {
		panic(err)
	}

	pkey2048 := pkey2048_any.(*rsa.PrivateKey)
	p2048 = pkey2048.Primes[0]
	q2048 = pkey2048.Primes[1]

	b4096, _ := pem.Decode([]byte(rsa4096))
	pkey4096_any, err := x509.ParsePKCS8PrivateKey(b4096.Bytes)
	if err != nil {
		panic(err)
	}

	pkey4096 := pkey4096_any.(*rsa.PrivateKey)
	p4096 = pkey4096.Primes[0]
	q4096 = pkey4096.Primes[1]
}

func getVDF() *VDF {
	return New(big.NewInt(5), big.NewInt(11))
}

func TestNew(t *testing.T) {
	_ = New(big.NewInt(5), big.NewInt(11))
}

func TestN(t *testing.T) {
	v := New(big.NewInt(5), big.NewInt(11))
	if v.N().Int64() != 5*11 {
		t.FailNow()
	}
}

func TestPow2tMod(t *testing.T) {
	v := getVDF()
	x := big.NewInt(11)
	m := big.NewInt(161)
	v.Pow2tMod(x, 8, m)

	if x.Cmp(big.NewInt(95)) != 0 {
		t.Fail()
	}
}

func TestPow2tMod_2(t *testing.T) {
	v := getVDF()
	x := big.NewInt(11)
	m := big.NewInt(161)
	v.Pow2tMod_2(x, 8, m)

	if x.Cmp(big.NewInt(95)) != 0 {
		t.Fail()
	}
}

func xTestEval(t *testing.T) {
	v := New(big.NewInt(p1), big.NewInt(q1))
	y := v.Eval(big.NewInt(x1), t1)

	if y.Cmp(big.NewInt(y1)) != 0 {
		t.Fail()
	}
}

func xTestVerify(t *testing.T) {
	v := New(big.NewInt(p1), big.NewInt(q1))
	pi := v.Eval(big.NewInt(x1), t1)

	// Case: the result is correct
	b := v.Verify(big.NewInt(x1), t1, pi)
	if b != true {
		t.Fail()
	}

	// Case: the result is incorrect
	b = v.Verify(big.NewInt(x1), t1-1, pi)
	if b == true {
		t.Fail()
	}

}

func TestEval_1024b(t *testing.T) {
	v := New(new(big.Int).Set(p1024), new(big.Int).Set(q1024))
	y := v.Eval(big.NewInt(65537), t1)

	if y.Cmp(y) != 0 {
		t.Fail()
	}
}

func TestVerify_1024b(t *testing.T) {
	v := New(new(big.Int).Set(p1024), new(big.Int).Set(q1024))
	pi := v.Eval(big.NewInt(65537), t1)

	// Case: the result is correct
	b := v.Verify(big.NewInt(65537), t1, pi)
	if b != true {
		t.Fail()
	}

	// Case: the result is incorrect
	b = v.Verify(big.NewInt(65537), t1-1, pi)
	if b == true {
		t.Fail()
	}

}

func BenchmarkPow2tMod(b *testing.B) {
	v := getVDF()

	x := big.NewInt(110001)
	// m := big.NewInt(161)
	m := big.NewInt(7)
	m.Exp(m, big.NewInt(100), nil)

	for i := 0; i < b.N; i++ {
		v.Pow2tMod(x, 1<<20, m)
	}
}

func BenchmarkPow2tMod_2(b *testing.B) {
	v := getVDF()

	x := big.NewInt(110001)
	//m := big.NewInt(161)
	m := big.NewInt(7)
	m.Exp(m, big.NewInt(100), nil)

	for i := 0; i < b.N; i++ {
		v.Pow2tMod_2(x, 1<<20, m)
	}
}

func BenchmarkEval_8b(b *testing.B) {
	v := New(big.NewInt(p1), big.NewInt(q1))
	for i := 0; i < b.N; i++ {
		v.Eval(big.NewInt(23), 2<<22)
	}
}

func BenchmarkVerify_8b(b *testing.B) {
	v := New(big.NewInt(p1), big.NewInt(q1))

	for i := 0; i < b.N; i++ {
		v.Verify(big.NewInt(23), 2<<22, big.NewInt(1))
	}
}

func BenchmarkEval_4096b(b *testing.B) {
	v := New(p4096, q4096)
	r := rand.New(rand.NewSource(1))
	x := new(big.Int).Rand(r, v.n)

	for i := 0; i < b.N; i++ {
		v.Eval(new(big.Int).Set(x), 2<<10)
	}
}

func BenchmarkVerify_4096b(b *testing.B) {
	v := New(p4096, q4096)
	r := rand.New(rand.NewSource(1))
	x := new(big.Int).Rand(r, v.n)

	for i := 0; i < b.N; i++ {
		v.Verify(x, 2<<20, big.NewInt(1))
	}
}
func BenchmarkEval_2048b(b *testing.B) {
	v := New(p2048, q2048)
	r := rand.New(rand.NewSource(1))
	x := new(big.Int).Rand(r, v.n)

	for i := 0; i < b.N; i++ {
		v.Eval(new(big.Int).Set(x), 2<<15)
	}
}

func BenchmarkVerify_2048b(b *testing.B) {
	v := New(p2048, q2048)
	r := rand.New(rand.NewSource(1))
	x := new(big.Int).Rand(r, v.n)

	for i := 0; i < b.N; i++ {
		v.Verify(x, 2<<15, big.NewInt(1))
	}
}
func BenchmarkEval_1024b(b *testing.B) {
	v := New(p1024, q1024)
	r := rand.New(rand.NewSource(1))
	x := new(big.Int).Rand(r, v.n)

	for i := 0; i < b.N; i++ {
		v.Eval(new(big.Int).Set(x), 2<<15)
	}
}

func BenchmarkVerify_1024b(b *testing.B) {
	v := New(p1024, q1024)
	r := rand.New(rand.NewSource(1))
	x := new(big.Int).Rand(r, v.n)

	for i := 0; i < b.N; i++ {
		v.Verify(x, 2<<15, big.NewInt(1))
	}
}

func BenchmarkEval_512b(b *testing.B) {
	v := New(p512, q512)
	r := rand.New(rand.NewSource(1))
	x := new(big.Int).Rand(r, v.n)

	for i := 0; i < b.N; i++ {
		v.Eval(new(big.Int).Set(x), 1<<20)
	}
}

func BenchmarkVerify_512b(b *testing.B) {
	v := New(p512, q512)
	r := rand.New(rand.NewSource(1))
	x := new(big.Int).Rand(r, v.n)

	for i := 0; i < b.N; i++ {
		v.Verify(x, 1<<30, big.NewInt(1))
	}
}

// func Benchmark2t(b *testing.B) {
// 	x := new(big.Int).SetString("78092a35516c42b06172bfe336d9ff45d04ab55f83e4f98d4d088f4818d2fe902811a55810cd9672afd3a30c6cb50b02700e0976aa209b8ef0c5341e9acb0442", 16)
// 	n := new(big.Int).SetString("be89e6a37225e1dd2fe9e7b11859a3c39d520d4af87f68f10db300fb7bc7a343819909df779103e394f511fba98299179819bf166a862ae158044903a1c7e04f", 16)

// 	c2t := big.NewInt(2)
// 	e := c2.Exp(c2, big.NewInt(20)
// }

func Benchmark3t(b *testing.B) {
	// 求  s = 2**(2**18)
	// 然后计算　x**s (mod m)
	s := new(big.Int)
	//for i := 0; i < b.N; i++ {
	t := big.NewInt(2)
	t.Exp(t, big.NewInt(20), nil)
	s = big.NewInt(2)
	s.Exp(s, t, nil)
	//}
	//fmt.Printf("%x\n", s)

	x, _ := new(big.Int).SetString("78092a35516c42b06172bfe336d9ff45d04ab55f83e4f98d4d088f4818d2fe902811a55810cd9672afd3a30c6cb50b02700e0976aa209b8ef0c5341e9acb0442", 16)
	n, _ := new(big.Int).SetString("be89e6a37225e1dd2fe9e7b11859a3c39d520d4af87f68f10db300fb7bc7a343819909df779103e394f511fba98299179819bf166a862ae158044903a1c7e04f", 16)

	for i := 0; i < b.N; i++ {
		x.Exp(x, s, n)
	}

}
