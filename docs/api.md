<a id="cSecp256k1"></a>

# cSecp256k1

`cSecp256k1` is a `ctypes` binding providing fast computation on `SECP256K1`
curve. `ECDSA` signature is about 140 times faster than [pure python]
(https://github.com/Moustikitos/elliptic-curve) implementation, `SCHNORR`
signature about 60 times faster.

<a id="cSecp256k1.rand_k"></a>

#### rand\_k

```python
def rand_k() -> int
```

Generate a random secp256k1 integer (in range [1..p]).

<a id="cSecp256k1.rfc6979_k"></a>

#### rfc6979\_k

```python
def rfc6979_k(msg: bytes,
              secret0: bytes,
              V: bytes = None) -> Tuple[int, bytes]
```

Generate a deterministic rfc6967 integer.

<a id="cSecp256k1.HexPoint"></a>

## HexPoint Objects

```python
class HexPoint(ctypes.Structure)
```

`ctypes` structure for secp256k1 curve point with `x`and `y` attributes as hex
bytes.

**Attributes**:

- `x` _bytes_ - point absisse as hex bytes
- `y` _bytes_ - point ordinate as hex bytes
  
```python
>>> import cSecp256k1 as cs
>>> G = cs.HexPoint(
...    b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
...    b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
>>> G.x  # return x value as hex bytes
b'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
>>> G[0]  # return x value as integer
55066263022277343669578718895168534326250603453777594175500187360389116729240
```
  
  Eliptic curve algebra is implemented with python operator `+` and `*`.
  
```python
>>> G * 2
<secp256k1 point:
    x:b'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
    y:b'1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
>
>>> G + G
<secp256k1 point:
    x:b'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
    y:b'1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
>
```

<a id="cSecp256k1.HexPoint.from_int"></a>

#### from\_int

```python
@staticmethod
def from_int(value: int)
```

Build curve point from integer absice.

<a id="cSecp256k1.HexPoint.from_hex"></a>

#### from\_hex

```python
@staticmethod
def from_hex(value: Union[bytes, str])
```

Build curve point from hex absice.

<a id="cSecp256k1.HexPoint.encode"></a>

#### encode

```python
def encode() -> str
```

Encode point as an hexadecimal bytes string.

<a id="cSecp256k1.HexSig"></a>

## HexSig Objects

```python
class HexSig(ctypes.Structure)
```

`ctypes` structure for secp256k1 signature with `r`and `s` attributes as hex
bytes.

**Attributes**:

- `r` _bytes_ - signature part `1` as hex bytes
- `s` _bytes_ - signature part `2` as hex bytes

<a id="cSecp256k1.HexSig.der"></a>

#### der

```python
def der() -> str
```

Encode signature as DER hexadecimal string.

<a id="cSecp256k1.HexSig.from_der"></a>

#### from\_der

```python
@staticmethod
def from_der(der: str)
```

Return HexSig object from a DER signature string.

<a id="cSecp256k1.HexSig.raw"></a>

#### raw

```python
def raw() -> str
```

Encode signature as RAW hexadecimal string.

<a id="cSecp256k1.HexSig.from_raw"></a>

#### from\_raw

```python
@staticmethod
def from_raw(raw: str)
```

Return HexSig object from RAW hexadecimal string.

<a id="cSecp256k1.PublicKey"></a>

## PublicKey Objects

```python
class PublicKey(HexPoint)
```

`ctypes` structure for secp256k1 public key with `x`and `y` attributes as hex
bytes. It is a subclass of [`HexPoint`](api.md#hexpoint-objects).

<a id="cSecp256k1.PublicKey.decode"></a>

#### decode

```python
@staticmethod
def decode(enc: Union[str, bytes])
```

Return PublicKey object from secp256k1-encoded bytes or string.

<a id="cSecp256k1.PublicKey.from_hex"></a>

#### from\_hex

```python
@staticmethod
def from_hex(secret)
```

Compute a PublicKey object from hexadecimal secret abcissa.

<a id="cSecp256k1.PublicKey.from_int"></a>

#### from\_int

```python
@staticmethod
def from_int(value: int)
```

Compute a PublicKey object from integer secret abcissa.

<a id="cSecp256k1.PublicKey.from_seed"></a>

#### from\_seed

```python
@staticmethod
def from_seed(seed: bytes)
```

Compute a PublicKey object from bytes secret abcissa.

<a id="cSecp256k1.PublicKey.from_secret"></a>

#### from\_secret

```python
@staticmethod
def from_secret(passphrase: str)
```

Compute a PublicKey object from secret passphrase.

