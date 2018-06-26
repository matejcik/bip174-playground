#!/usr/bin/env python3
import binascii
import os
import sys

import construct as c
from construct import this, len_

from .compact_uint import CompactUint


class ConstFlag(c.Adapter):
    def __init__(self, const):
        self.const = const
        super().__init__(c.Optional(c.Const(const)))

    def _encode(self, obj, context, path):
        return self.const if obj else None

    def _decode(self, obj, context, path):
        return obj is not None


TxInput = c.Struct(
    "tx" / c.Bytes(32),
    "index" / c.Int32ul,
    # TODO coinbase tx
    "script" / c.Prefixed(CompactUint, c.GreedyBytes),
    "sequence" / c.Int32ul,
)

TxOutput = c.Struct(
    "value" / c.Int64ul,
    "pk_script" / c.Prefixed(CompactUint, c.GreedyBytes),
)

StackItem = c.Prefixed(CompactUint, c.GreedyBytes)
TxInputWitness = c.PrefixedArray(CompactUint, StackItem)

Transaction = c.Struct(
    "version" / c.Int32ul,
    "segwit" / ConstFlag(b"\x00\x01"),
    "inputs" / c.PrefixedArray(CompactUint, TxInput),
    "outputs" / c.PrefixedArray(CompactUint, TxOutput),
    "witness" / c.If(this.segwit, TxInputWitness[len_(this.inputs)]),
    "lock_time" / c.Int32ul,
    c.Terminated,
)


if __name__ == "__main__":
    if os.isatty(sys.stdin.fileno()):
        tx_hex = input("Enter transaction in hex format: ")
    else:
        tx_hex = sys.stdin.read().strip()

    tx_bin = binascii.unhexlify(tx_hex)

    print(Transaction.parse(tx_bin))
