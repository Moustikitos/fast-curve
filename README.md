# fast-curve
ctypes implementation for bitcoin curve `secp256k1`

## Install

### From github

```shell
python -m pip install git+https://github.com/Moustikitos/fast-curve.git
```

### Dependencies

```shell
sudo apt-get install python3-dev libgmp3-dev
```

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
>>> import hashlib
>>> # generate a public key from explicit secret
>>> cs.G * int(hashlib.sha256(b"secret").hexdigest(), 16)
<secp256k1 point:
  x:b'a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933'
  y:b'924aa2580069952b0140d88de21c367ee4af7c4a906e1498f20ab8f62e4c2921'
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
