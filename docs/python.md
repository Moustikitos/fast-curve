<a name="cSecp256k1"></a>
# cSecp256k1

`cSecp256k1` is a `ctypes` binding that provides fast computation on
`SECP256K1` curve. `ECDSA` signature is about 140 times faster than [pure
python](https://github.com/Moustikitos/elliptic-curve) implementation,
`SCHNORR` signature about 60 times faster.

<a name="cSecp256k1.rand_k"></a>
#### rand\_k

```python
rand_k()
```

Generate a random secp256k1 integer (in range [1..p]).

<a name="cSecp256k1.rfc6979_k"></a>
#### rfc6979\_k

```python
rfc6979_k(msg, secret0, V=None)
```

Generate a deterministic rfc6967 integer.

<a name="cSecp256k1.HexPoint"></a>
## HexPoint Objects

```python
class HexPoint(ctypes.Structure)
```

`ctypes` structure for secp256k1 curve point with `x`and `y` attributes
as hex bytes.

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
55066263022277343669578718895168534326250603453777594175500187360389116729\
240
```
  
  Eliptic curve algebra is implented with python operator `+` and `*`.
  
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

<a name="cSecp256k1.HexPoint.from_int"></a>
#### from\_int

```python
 | @staticmethod
 | from_int(value)
```

Build curve point from integer absice.

<a name="cSecp256k1.HexPoint.from_hex"></a>
#### from\_hex

```python
 | @staticmethod
 | from_hex(value)
```

Build curve point from hex string absice.

<a name="cSecp256k1.HexPoint.encode"></a>
#### encode

```python
 | encode()
```

Encode point as a hex bytes.

<a name="cSecp256k1.HexSig"></a>
## HexSig Objects

```python
class HexSig(ctypes.Structure)
```

`ctypes` structure for secp256k1 signature with `r`and `s` attributes
as hex bytes.

**Attributes**:

- `r` _bytes_ - signature part `1` as hex bytes
- `s` _bytes_ - signature part `2` as hex bytes

<a name="cSecp256k1.HexSig.der"></a>
#### der

```python
 | der()
```

Generate DER signature as hexadecimal bytes string.

<a name="cSecp256k1.HexSig.from_der"></a>
#### from\_der

```python
 | @staticmethod
 | from_der(der)
```

Return HexSig object from a DER signature string.

<a name="cSecp256k1.HexSig.raw"></a>
#### raw

```python
 | raw()
```

Generate RAW signature as hexadecimal bytes string.

<a name="cSecp256k1.HexSig.from_raw"></a>
#### from\_raw

```python
 | @staticmethod
 | from_raw(raw)
```

Return HexSig object from a RAW signature string.

