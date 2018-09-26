# Collusion (Crypto, 500)
Author: fxrh

**Note: As LaTex (aka those math symbols) do not work on github, go [here](https://md.darmstadt.ccc.de/collusion) for a version with proper math symbols**

Collusion was a Crypto-Challenge at the Qualification Round of CSAW CTF 2018.

We were given five files:
* ```common.go```, a Go implementation of a crypto system
* ```generate_challenge.go```, which generated the challenge given to us
* ```bobs-key.json```, Bob's private key, and ```carols-key.json```, Carol's private key
* ```message.json```, a message encrypted for Alice

## The Crypto System

Collusion uses an identity-based encryption, in which a message can be encrypted for a Person using for example their name. For this, a trusted third party must exist which generates a master private key and distributes private keys to all parties.

In this case, the trusted third party is called a Group. On creation, it generates two primes $P$ and $Q$, calculates $N=P\cdot Q$ (so far, standard RSA) and generates a $x<phi(N)$ at random.

```go
type Group struct {
	P, Q *big.Int
	X    *big.Int
}

func NewGroup(src io.Reader, bits int) (*Group, error) {
	p, err := generateSafe(src, bits/2)
	if err != nil {
		return nil, err
	}
	q, err := generateSafe(src, bits/2)
	if err != nil {
		return nil, err
	}

	x, err := rand.Int(src, phi(p, q))
	if err != nil {
		return nil, err
	}
	x.SetBit(x, 0, 0)

	return &Group{p, q, x}, nil
}
```

Now, for each identity (e.g., for Alice), the crypto system calculates a random looking, but deterministic value $n$ smaller than $phi(N)$. Then, it generates for each identity the private key for each identity by inverting $(x+n)$ modulo $phi(N)$, and sends these private keys to the corresponding idenities:

```go
func (g *Group) Decrypter(id string) (*Decrypter, error) {
	N := new(big.Int).Mul(g.P, g.Q)

	n, err := DecrypterId(id, N)
	if err != nil {
		return nil, err
	}
	phiN := phi(g.P, g.Q)
	d := new(big.Int).Add(g.X, n)
	d.Mod(d, phiN).ModInverse(d, phiN)

	return &Decrypter{N, d}, nil
}
```

Now, anyone that has access to $x$ can encrypt something for identity $n$ by calculating $c = m^{x+n}$ and that identity can decrypt it by calculating $m = c^{(x+n)^{-1}}$. Note that $x+n$ can be seen as the $e$ in a RSA encryption system and $(x+n)^{-1}$ as the corresponding $d$. But instead of giving the Encrypter access to the $x$, it is given $3^x$.

```go
func (g *Group) Encrypter() *Encrypter {
	N := new(big.Int).Mul(g.P, g.Q)

	H := big.NewInt(3)
	H.Exp(H, g.X, N)

	return &Encrypter{N, H}
}
```

A pair of Encrypter and Decrypter can use their values to generate a shared private key: The Encrypter generates a random value $r < N$ and calculates $c = 3^{(x+n)r}$ and sends this to the Decrypter. The Decryptor can recover $3^r = c^{(x+n)^{-1}}$. Now, both can use sha256($3^r$) as shared key. In this case, it is used as key for AES-GCM.

```go
func (e *Encrypter) GenerateKey(src io.Reader, id string) (*big.Int, []byte, error) {
	n, err := DecrypterId(id, e.N)
	if err != nil {
		return nil, nil, err
	}
	r, err := rand.Int(src, e.N)
	if err != nil {
		return nil, nil, err
	}

	V := big.NewInt(3)
	V.Exp(V, n, e.N).Mul(V, e.H).Mod(V, e.N).Exp(V, r, e.N)

	K := big.NewInt(3)
	K.Exp(K, r, e.N)
	shared := sha256.Sum256(K.Bytes())

	return V, shared[:], nil
}

func (e *Encrypter) GenerateKey(src io.Reader, id string) (*big.Int, []byte, error) {
	n, err := DecrypterId(id, e.N)
	if err != nil {
		return nil, nil, err
	}
	r, err := rand.Int(src, e.N)
	if err != nil {
		return nil, nil, err
	}

	V := big.NewInt(3)
	V.Exp(V, n, e.N).Mul(V, e.H).Mod(V, e.N).Exp(V, r, e.N)

	K := big.NewInt(3)
	K.Exp(K, r, e.N)
	shared := sha256.Sum256(K.Bytes())

	return V, shared[:], nil
}

func Encrypt(e *Encrypter, recipient, message string) (*Payload, error) {
	V, shared, err := e.GenerateKey(rand.Reader, recipient)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciph, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	body := ciph.Seal(nil, nonce, []byte(message), nil)

	return &Payload{V, nonce, body}, nil
}
```

## The Challenge

Looking at ```generate_challenge.go```, we see that the flag is encrypted for the identity Alice. However, we only get access to the Decrypters for Bob and Carol. (Note that we were not given encryptor.json - we first thought this to be a mistake, but the orga told us this was on purpose.)

```go
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	g, err := NewGroup(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}
	e := g.Encrypter()

	if err := saveToFile("encrypter.json", e); err != nil {
		log.Fatal(err)
	}

	payload, err := Encrypt(e, "Alice", "flag{someflag}")
	if err != nil {
		log.Fatal(err)
	} else if err := saveToFile("message.json", payload); err != nil {
		log.Fatal(err)
	}

	dB, err := g.Decrypter("Bob")
	if err != nil {
		log.Fatal(err)
	} else if err := saveToFile("bobs-key.json", dB); err != nil {
		log.Fatal(err)
	}

	dC, err := g.Decrypter("Carol")
	if err != nil {
		log.Fatal(err)
	} else if err := saveToFile("carols-key.json", dC); err != nil {
		log.Fatal(err)
	}
}
```

From now on, we will use $n_A$ for the identity "Alice", $n_B$ for "Bob" and $n_C$ for "Carol". Looking at the message.json file, we have $V$, which is the encrypted shared key $3^{(x+n_A)r}$, and the ciphertext (Body) and Nonce for the AES-GCM. 

```javascript=
{"V":584221881758507213769903010020339815950057645818648920364983549601225341062365062520391665711126204114735381305339677935863870281557078300036090892608892021129276590502981260857531205402850896018739268436262147451812156349860568744247316332461855247671922521643140703633415753776548859345314133294397634741631,"Nonce":"2NXgQhueKbVm5Pd8","Body":"0ZWAaAxvazGfyTJSRPkyeHU9ZUSWSoWFObggHmmfb835TWFAzA=="}
```

As AES-GCM is probably secure, we have to somehow recover $3^r$ to decrypt the flag. However, at first glance, the crypto system looks quite secure: we can't get $r$ directly from $V$, as this would mean we have an efficient solution to the discrete logarithm problem (which would break most of our current crypto). As $x$ is random, $x+n_B$ and $(x+n_B)^{-1}$ are random, too, and can't really help us (same for $n_C$).

However, while the Decryptors don't help on their own, put together, they give us some information about $phi(N)$: We know the difference of $(x+n_B)$ and $(x+n_C)$, $n_C-n_B$, as well as the difference of their inverses modulo $phi(N)$, $(x+n_C)^{-1}-(x+n_B)^{-1}$. Can we use this information to calculate $phi(N)$?

Recall what we have access to: We have $N, n_A, n_B, n_C, V, (x+n_B)^{-1}, (x+n_C)^{-1}$. We define $\Delta=n_C-n_B$. Then, we have the following two equations:
$(x+n_B)\cdot(x+n_B)^{-1} -1 = k\cdot phi(N)$
$(x+n_B+\Delta)\cdot(x+n_B+\Delta)^{-1} -1 = k^\prime\cdot phi(N)$
We can rewrite the second equation as
$(x+n_B)\cdot(x+n_B+\Delta)^{-1}+\Delta\cdot(x+n_B+\Delta)^{-1} -1 = k^\prime\cdot phi(N)$
Note that in this equation, we know everything but $(x+n_B)$. Further, we know $(x+n_B)^{-1}$, so we can multiply with it on both sides!
$(x+n_B+\Delta)^{-1}+(x+n_B)^{-1}\cdot\Delta\cdot(x+n_B+\Delta)^{-1}-(x+n_B)^{-1} = k^{\prime\prime}\cdot phi(N)$
Removing the delta, we get:
$(x+n_C)^{-1}+(x+n_B)^{-1}\cdot(n_C-n_B)\cdot(x+n_C)^{-1} - (x+n_B)^{-1} = k^{\prime\prime}\cdot phi(N)$
So we can calculate a multiple of $phi(N)$!

First, assume we would have $phi(N)$ and not a multiple of it. Then, we could first invert $(x+n_B)^{-1}$ to get $x+n_B$ and subtract $n_B$ to get $x$. Then, we can invert $x+n_A$ to get $(x+n_A)^{-1}$, the Decrypter for Alice.

We can actually do the same with $k^{\prime\prime}\cdot phi(N)$! An inverse modulo a multiple of $phi(N)$ is also an inverse modulo $phi(N)$ itself. We just get a lot bigger numbers! However, as soon as we decrypt V, everything is taken modulo N, so we get the same number at the end.

Let's do this!

First, we calculated $n_B, n_C$ using a small Go snippet, so we could switch to python/sage afterwards.
```python
id_bob = 110986239228452276705243281071881479737523902719947647938060491211704764431880660457345141212455880526555282371426548091232174507173827515718646915260209209310984096008076553763193605528007494132681243769355257049176601319896119207555664923628139878933762458235186384695655511029359951266896240850577326410847
id_carol = 583129794620057172041414492769532788882308497426816540237528911270980784413031234372076289886835523421627738969856610949474646027544481682356089526799158873823065009381766069792920961225733009587409217848190549789528049828831581381820075636559808718782002074561483173403454270926730507401383754487989217146469
V = 584221881758507213769903010020339815950057645818648920364983549601225341062365062520391665711126204114735381305339677935863870281557078300036090892608892021129276590502981260857531205402850896018739268436262147451812156349860568744247316332461855247671922521643140703633415753776548859345314133294397634741631
````
We calculate $k^{\prime\prime}\cdot phi(N)$ (```D_bob``` denotes the Decrypter for Bob):
```python
k_phi = D_carol + D_carol*(id_carol-id_bob)*D_bob-D_bob
```
Then, we can calculate $3^r$:
```python
E_bob = inverse_mod(D_bob, k_phi)
x_k = E_bob - id_bob
D_alice = inverse_mod(x_k+id_alice, k_phi)
key = pow(V, D_alice, N)
```
Now, we just need to decrypt the AES ciphertext using sha256(key) as key:
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Utils.number import long_to_byte, byte_to_long
from hashlib import sha256
from base64 import b64decode, b64encode

key_bytes = long_to_bytes(key)
aes_key = sha256(key_bytes).digest()
Nonce = "2NXgQhueKbVm5Pd8"
Nonce = b64decode(Nonce)
Body = b64decode("0ZWAaAxvazGfyTJSRPkyeHU9ZUSWSoWFObggHmmfb835TWFAzA==")

aesgcm =AESGCM(aes_key)
aesgcm.decrypt(Nonce, Body, associated_data=None)
```
And there is the flag: ```b'flag{mission payload}'```






