# vdf
A verifiable delay function based on cyclic group $\mathbb{Z} \big/ n\mathbb{Z}$

## Usage
```go
// Init an VDF instance
// See Note section to learn how to pick q and n
p = big.NewInt(5)
q = big.NewInt(11)
v := vdf.New(p, q)


// Eval an proof
x := big.NewInt(7)
t := 1<<20
y := vdf.Eval(x, t)

fmt.Printf("7^(2^(2^20)) mod %v == %v\n", v.N(), y)


// Verify the proof
isValid := vdf.Verify(big.NewInt(7), t, y)

fmt.Printf("isValid == %v\n", isValid)

```

There is a demo on go playground: https://go.dev/play/p/hLBsSgbHn2a


## Math

We have a VDF function initalized with prime `P` and `Q`. 

Now we calcualte 

$$
N = P * Q
$$

The eval function calculates:

$$
y = x^{2^{t}} \mod N
$$

Where `x` is a random number, `t` is hardness.

The time complexity of eval function is $O(t)$.

The verify function calculates:

$$
s = (P - 1) \times (Q - 1)
$$

$$
r = 2^{t} \mod s
$$

$$
y = x^{r} \mod N
$$

The time complexity of verify function is $O(\log{}{t})$.


## Note

* When t == $2^{20}$, and with 512 bits N, it takes about 2 seconds to eval and 1ms to verify on an Ryzen 5 2600 CPU.

* It is strongly recommend pick P and Q with an RSA key generator.

## Generate P and Q with Golang

```go
import (
    "crypto/rsa"
    "crypto/rand"
)

// Generate 512 bits RSA key
rsaKey, err := rsa.GenerateKey(rand.Reader, 512)

p := rsaKey.Primes[0]
q := rsaKey.Primes[1]

fmt.Printf("p = %v, q = %v\n", p, q)

```


