# fast-curve
`ctypes` implementation for bitcoin curve `secp256k1`. It is 100 times faster than pure python implementation and may be even faster if used in lower level development languages.

### Support this project
 
 [![Liberapay receiving](https://img.shields.io/liberapay/goal/Toons?logo=liberapay)](https://liberapay.com/Toons/donate)
 
 [Buy &#1126;](https://bittrex.com/Account/Register?referralCode=NW5-DQO-QMT) and:
 
   * [X] Send &#1126; to `AUahWfkfr5J4tYakugRbfow7RWVTK35GPW`
   * [X] Vote `arky` on [Ark blockchain](https://explorer.ark.io) and [earn &#1126; weekly](http://dpos.arky-delegate.info/arky)


## Dependencies

### Ubuntu

```shell
sudo apt-get install python3-dev libgmp3-dev libgmp3
```

### Windows

Download [Msys2](https://www.msys2.org) and [install](https://www.msys2.org/#installation)
it into `C:\Msys` folder, run `MSYS2` and execute:

```bash
pacman -Syu
```

Download [libgmp](https://gmplib.org/) archive and extract it into `C:\Msys\home\{USER}`
folder. Then, runing MSYS2 from libgmp root folder execute:

```bash
./condigure
make
make check
make install
```

Use `C:\Msys\mingw64\python.exe` to run install command. The built package
can be moved into any python 3.x distribution path.

## install command

```shell
python -m pip install git+https://github.com/Moustikitos/fast-curve.git
```

For **Windows users**, a built package is available
[here](https://github.com/Moustikitos/fast-curve/raw/master/download/cSecp256k1-1.0.2-win32.7z).
Exctract content anywhere in python path defined by `sys.path`.

## Quick start

### Algebra

```python
>>> import cSecp256k1 as cs
>>> cs.G
<secp256k1 point:
  x:b'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  y:b'483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
>
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

### Public Keys

```python
>>> import cSecp256k1 as cs
>>> # generate a public key from explicit secret
>>> puk = cs.PublicKey.from_secret("secret")
>>> puk
<secp256k1 point:
  x:b'a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933'
  y:b'924aa2580069952b0140d88de21c367ee4af7c4a906e1498f20ab8f62e4c2921'
>
>>> puk.encode()
b'03a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933'
>>> cs.PublicKey.decode(puk.encode())
<secp256k1 point:
  x:b'a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933'
  y:b'924aa2580069952b0140d88de21c367ee4af7c4a906e1498f20ab8f62e4c2921'
>
>>> puk2 = cs.PublicKey.from_secret("secret2")
>>> # combined public key
>>> puk + puk2
<secp256k1 point:
  x:b'62a775dba8a7b2e6c839073e8300a2ec56c36671a066de92a39f4789eee635d6'
  y:b'858f2ffbe8cfaed3655abcdf7796c8e16a0bb137c84810f200bfb4a37bbb8867'
>
```

### Keyring

```python
>>> import cSecp256k1 as cs
>>> # generate key pair using passphrase
>>> k = cs.KeyRing("secret")
>>> k  # k is a big integer
19774644322343364210033507226347517504509547448996271814774638767344332546651
>>> "%64x" % k
'2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b'
>>> k.puk()  # retrieve associated public key
<secp256k1 point:
  x:b'a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933'
  y:b'924aa2580069952b0140d88de21c367ee4af7c4a906e1498f20ab8f62e4c2921'
>
>>> k.puk().encode() 
b'03a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933'
```

### Issuing signatures

#### Ecdsa
```python
>>> import cSecp256k1 as cs
>>> e = cs.Ecdsa("secret")
>>> e.sign("simple message as string")
<secp256k1 signature:
  r:b'ff5558ac0366bf794c72648cb3fbd591910f599d8a2737fb72820d121d1a704a'
  s:b'74824580157a04b004609297ca0d92e390e989a38df05ea80753c938b73acf66'
>
>>> e.sign("simple message as string", rfc6979=True)
<secp256k1 signature:
  r:b'd7b0a8a15ac4eedb6286a29b6ff25f945b22d75a73763547a9f9b9f4436ece81'
  s:b'2d919c85e43c5f200b3aa09eec0f1930fee67b4ad19994ab9df2cd85a35eb482'
>
>>> sig = e.sign("simple message as string")
>>> e.verify("simple message as string", sig)
True
```

#### Schnorr

```python
>>> import cSecp256k1 as cs
>>> s = cs.Schnorr("secret")
>>> s.sign("simple message as string")  
<secp256k1 signature:
  r:b'58957262a9180545d17e05bf16bd429e06f8b2c882e1e9beaf79675b49703dc4'
  s:b'b1416e5ee442875dacb00dc3c2bd063ab5ee6164d0c1148e6728bc66c1f9bd2b'
>
>>> sig = s.sign("simple message as string")
>>> s.verify("simple message as string", sig)
True
```

### Signature format

An elliptic curve digital signature is a set of two integers, `r` and `s`.
There are several ways to represent such signature with a string. `cSec256k1`
package implements 2 of them: `RAW` and `DER`.

```python
>>> import cSecp256k1 as cs
>>> s = cs.Schnorr("secret")
>>> sig = s.sign("simple message as string")
>>> sig.raw()
b'264745e87fe0d327a5b5b9162d612f4ca433e5752e9ab8de5c1d98ad063cff43303b3f6aeefe6aee418d578511be88c8a562f906a10ef433f842985be3a6a5db'
>>> sig.der()
b'30440220264745e87fe0d327a5b5b9162d612f4ca433e5752e9ab8de5c1d98ad063cff430220303b3f6aeefe6aee418d578511be88c8a562f906a10ef433f842985be3a6a5db'
>>> cs.HexSig.from_der(sig.der())
<secp256k1 signature:
  r:b'264745e87fe0d327a5b5b9162d612f4ca433e5752e9ab8de5c1d98ad063cff43'
  s:b'303b3f6aeefe6aee418d578511be88c8a562f906a10ef433f842985be3a6a5db'
>
>>> cs.HexSig.from_raw(sig.raw())
<secp256k1 signature:
  r:b'264745e87fe0d327a5b5b9162d612f4ca433e5752e9ab8de5c1d98ad063cff43'
  s:b'303b3f6aeefe6aee418d578511be88c8a562f906a10ef433f842985be3a6a5db'
>
```

### Issuing Ark signatures

**`arky` delegate private key used here**.

#### ECDSA (DER)
```python
>>> import cSecp256k1 as cs
>>> # if no secret given, it is asked via terminal input
>>> e = cs.Ecdsa()
Type or paste your passphrase >
>>> sig = e.sign("simple message", rfc6979=True, canonical=True)
>>> sig.der().encode()
'3045022100f6f8e63b02d8a729ab8aca1a49348463ddb35ee1b27e07002ffb2be49ce3058502206cf2827da8c4a52c32e2235d6558ccdcc49fabe2da7466a1472b41d6e50ad3a4'
```

#### Schnorr (RAW)
```python
>>> import cSecp256k1 as cs
>>> # ark uses bcrypto 4.10 schnorr signature
>>> b = cs.Bcrpt410()
Type or paste your passphrase >
>>> sig = b.sign("simple message") 
>>> sig.raw().decode()
'928956e9f4bc1694521eea7dd72be706b26c2b4945b7c36e4f384d81a2292e71c2dda0a3e1c2a96578bb552a6f8e652014b4333bb37449f08b1e4f0076b3dd9f'
```
