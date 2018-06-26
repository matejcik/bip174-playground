# BIP 174 format playground

Small script that parses and regenerates variants of the BIP 174 scheme.

Requires Python 3 and `construct`. Protobuf is based on
[`trezorlib`](https://github.com/trezor/python-trezor) implementation,
extended to support Fixed32 fields. It doesn't support packed arrays
though, which messes up the measurement a little.

Presumes UNIX-based environment, only tested on Linux but should
work elsewhere too.

## Installation and usage

Create and activate a virtualenv:
```sh
python3 -m venv virtualenv
source virtualenv/bin/activate
pip install -r requirements.txt
```

Feed one of the test vectors (taken from [here](https://github.com/achow101/bips/blob/bip174-rev/bip-0174.mediawiki#Specification)) to the tool:
```sh
python3 analyze.py < case-sighash.hex
```
