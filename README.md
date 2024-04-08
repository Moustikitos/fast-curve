# fast-curve

`ctypes` implementation for bitcoin curve `secp256k1`. It is 100 times faster than pure python implementation and may be even faster if used in lower level development languages.


# Dependencies

## Ubuntu

```shell
sudo apt-get install python3-dev libgmp3-dev libgmp3
```

## Windows

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

# install command

```shell
python -m pip install git+https://github.com/Moustikitos/fast-curve.git
```

For **Windows users**, a built package is available
[here](https://github.com/Moustikitos/fast-curve/raw/master/download/cSecp256k1-1.1.1-win64.7z).
Exctract content anywhere in python path defined by `sys.path`.

# Versions

## 1.1.2
 - [x] typing update

## 1.1.1
 - [x] exclusive use of `hash_sha256_s` in `schnorr.c`

## 1.0.6
 - [x] bugfix in `bcrypto410_*` schnorr signature

## 1.0.5
 - [x] minor C code tweaks
 - [x] minor `setup.py` module tweaks

## 1.0.4
 - [x] C code improvement
 - [x] code coverage improvement
 - [x] pydoc-markdown documentation added

## 1.0.3
 - [x] ecdsa signature support
 - [x] bcrypto 4.10 schnorr signature support
 - [x] [BIP0340 sipa](https://github.com/sipa/bips/tree/3b1fb9600b938172dd98a63e4906a861af9c3ab0/bip-0340) shnorr signatures support

## Support this project

<!-- [![Liberapay receiving](https://img.shields.io/liberapay/goal/Toons?logo=liberapay)](https://liberapay.com/Toons/donate) -->
[![Paypal me](https://img.shields.io/badge/PayPal-toons-00457C?logo=paypal&logoColor=white)](https://paypal.me/toons)
[![Bitcoin](https://img.shields.io/badge/Donate-bc1q6aqr0hfq6shwlaux8a7ydvncw53lk2zynp277x-ff9900?logo=bitcoin)](https://github.com/Moustikitos/python-mainsail/blob/master/docs/img/bc1q6aqr0hfq6shwlaux8a7ydvncw53lk2zynp277x.png)
