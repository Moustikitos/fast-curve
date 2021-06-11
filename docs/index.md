# About

`cSecp256k1` package is a `ctypes` implementation for `scp256k1` curve algebra
and digital signatures running on both python 2.x and 3.x.

# Operating Systems Supported

This package targets Linux, MacOS and Windows  operating systems. Due to the
dependency on the GMP C library, refer to [project readme](README.md) in order
to build this package on Windows.

# Quick view
```py
>>> import cSecp256k1 as cs
```

## `secp256k1` curve constants:

```py
>>> cs.G  # generator point
<secp256k1 point:
  x:b'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  y:b'483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
>
>>> cs.G[0]
55066263022277343669578718895168534326250603453777594175500187360389116729240
>>> cs.G[1]
32670510020758816978083085130507043184471273380659243275938904335757337482424
>>> cs.n
115792089237316195423570985008687907852837564279074904382605163141518161494337
>>> cs.p
115792089237316195423570985008687907853269984665640564039457584007908834671663
>>>
```

## Algebra

```python
>>> cs.G * 2
<secp256k1 point:
  x:b'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
  y:b'1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
>
>>> cs.G + cs.G
<secp256k1 point:
  x:b'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
  y:b'1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
>
```

## Key pair

Private and public keys are issued using a `KeyRing` object. There are several
ways to initiate a `KeyRing`:

```py
>>> # passphrase asked via terminal
>>> k = cs.KeyRing()
Type or paste your passphrase > 
>>> # k is actualy a python integer instance
>>> k
19774644322343364210033507226347517504509547448996271814774638767344332546651
>>> # giving a passphrase (as bytes or str)
>>> cs.KeyRing(b"secret")
19774644322343364210033507226347517504509547448996271814774638767344332546651
>>> cs.KeyRing("secret")
19774644322343364210033507226347517504509547448996271814774638767344332546651
>>> # giving an integer
>>> cs.KeyRing(k)
19774644322343364210033507226347517504509547448996271814774638767344332546651
```

`KeyRing` object is an integer representing the secret abscissa also known as
private key. From it the public key can be retrived using generator point:

```py
>>> puk = cs.G * k  # k * cs.G raises an Exception
>>> puk
<secp256k1 point:
  x:b'a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933'
  y:b'924aa2580069952b0140d88de21c367ee4af7c4a906e1498f20ab8f62e4c2921'
>
>>> # secp256k1 point representation
>>> puk.encode()
b'03a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933'
```

A specific method is defined for that purpose:

```py
>>> puk = k.puk()
<secp256k1 point:
  x:b'a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933'
  y:b'924aa2580069952b0140d88de21c367ee4af7c4a906e1498f20ab8f62e4c2921'
>
```

## Issuing signature

Two specific `Keyring` subclasses are defined to that purpose:

### `ECDSA` signatures

```python
>>> import cSecp256k1 as cs
>>> e = cs.Ecdsa("secret")
>>> sig1 = e.sign("simple message as string")
>>> sig2 = e.sign("simple message as string", rfc6979=True)
>>> sig1
<secp256k1 signature:
  r:b'ff5558ac0366bf794c72648cb3fbd591910f599d8a2737fb72820d121d1a704a'
  s:b'74824580157a04b004609297ca0d92e390e989a38df05ea80753c938b73acf66'
>
>>> sig2
<secp256k1 signature:
  r:b'd7b0a8a15ac4eedb6286a29b6ff25f945b22d75a73763547a9f9b9f4436ece81'
  s:b'2d919c85e43c5f200b3aa09eec0f1930fee67b4ad19994ab9df2cd85a35eb482'
>
>>> e.verify("simple message as string", sig1)
True
>>> e.verify("simple message as string", sig2)
True
```

### `SCHNORR` signatures

```py
>>> s = cs.Schnorr("secret")
>>> sig = s.sign("simple message")
>>> sig
<secp256k1 signature:
  r:b'8b34bfacb66585405f0a08bb87ba3d7ac1637d1807c78a5b53df0313c7f211d8'
  s:b'77105ad3d604a1b7c93f100985378c17541f4cd41e5395195bbac8d6cae8151b'
>
```

## Encoding/decoding signature

An elliptic curve digital signature is a set of two integers, `r` and `s`.
There are several ways to represent such signature with a string. `cSec256k1`
package implements 2 of them: `RAW` and `DER`.

```python
>>> import cSecp256k1 as cs
>>> s = cs.Schnorr("secret")
>>> sig = s.sign("simple message as string")
>>> sig
<secp256k1 signature:
  r:b'5ad683cb3681089fdfa36d89da8394cc9186b255ddd56242cf9e1546b868df0b'
  s:b'cbb28168bf5976123a84a485c56afac221bb65a01b92f3530a1112caffdac9a6'
>
>>> # encode signature as RAW and DER
>>> raw = sig.raw()
>>> raw
b'5ad683cb3681089fdfa36d89da8394cc9186b255ddd56242cf9e1546b868df0bcbb28168bf5976123a84a485c56afac221bb65a01b92f3530a1112caffdac9a6'
>>> der = sig.der()
>>> der
b'304502205ad683cb3681089fdfa36d89da8394cc9186b255ddd56242cf9e1546b868df0b022100cbb28168bf5976123a84a485c56afac221bb65a01b92f3530a1112caffdac9a6'
>>> # decode signature from RAW and DER
>>> s.sig(raw) 
<secp256k1 signature:
  r:b'5ad683cb3681089fdfa36d89da8394cc9186b255ddd56242cf9e1546b868df0b'
  s:b'cbb28168bf5976123a84a485c56afac221bb65a01b92f3530a1112caffdac9a6'
>
>>> s.sig(der)
<secp256k1 signature:
  r:b'5ad683cb3681089fdfa36d89da8394cc9186b255ddd56242cf9e1546b868df0b'
  s:b'cbb28168bf5976123a84a485c56afac221bb65a01b92f3530a1112caffdac9a6'
>
```

## Issuing [Ark.io](https://ark.io) signatures

### ECDSA (DER)
```python
>>> import cSecp256k1 as cs
>>> # if no secret given, it is asked via terminal input
>>> e = cs.Ecdsa()
Type or paste your passphrase >
>>> sig = e.sign("simple message", rfc6979=True, canonical=True)
>>> sig.der().decode()
'3045022100f6f8e63b02d8a729ab8aca1a49348463ddb35ee1b27e07002ffb2be49ce3058502206cf2827da8c4a52c32e2235d6558ccdcc49fabe2da7466a1472b41d6e50ad3a4'
```

### Schnorr (RAW)
```python
>>> import cSecp256k1 as cs
>>> # ark.io blockchain uses bcrypto 4.10 schnorr signatures
>>> b = cs.Bcrpt410()
Type or paste your passphrase >
>>> sig = b.sign("simple message") 
>>> sig.raw().decode()
'928956e9f4bc1694521eea7dd72be706b26c2b4945b7c36e4f384d81a2292e71c2dda0a3e1c2a96578bb552a6f8e652014b4333bb37449f08b1e4f0076b3dd9f'
```

<!-- # Sources and documentations
 1. Schnorr signatures
    + [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
    + [BIP 340 Python reference](https://github.com/sipa/bips/blob/bip-taproot/bip-0340/reference.py)
    + [Bcrypto 4.10 schnorr](https://github.com/bcoin-org/bcrypto/blob/v4.1.0/lib/js/schnorr.js)
 2. RFC 6979
    + []()
 3. ArkEcosystem
    + []() -->
