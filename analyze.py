import os, sys, binascii
from io import BytesIO

import construct as c

from formats.compact_uint import CompactUint
from formats.transaction import Transaction
from formats import bip174, protobuf

HARDENED_FLAG = 1 << 31

# current key-value based format:

KeyValue = c.Struct(
    "key" / c.Prefixed(CompactUint, c.Struct(
        "type" / c.Byte,
        "data" / c.GreedyBytes,
    )),
    "value" / c.Prefixed(CompactUint, c.GreedyBytes),
    "ofs" / c.Tell,
)

Sequence = c.FocusedSeq("content",
    "content" / c.GreedyRange(
        c.FocusedSeq(
            "keyvalue",
            "terminator" / c.Peek(c.Byte),
            c.StopIf(c.this.terminator == 0),
            "keyvalue" / KeyValue,
        )
    ),
    c.Const(b'\0'),
)

PSBT = c.Struct(
    "magic" / c.Const(b'psbt'),
    "sep" / c.Const(b'\xff'),
    "general" / Sequence,
    "transaction" / c.RestreamData(c.this.general[0].value, Transaction),
    "inputs" / c.Array(c.len_(c.this.transaction.inputs), Sequence),
    "outputs" / c.Array(c.len_(c.this.transaction.outputs), Sequence),
    c.Terminated,
)

# key-less format:

ValueOnly = c.Prefixed(CompactUint, c.Struct(
    "type" / c.Byte,
    "value" / c.GreedyBytes,
))

ValueSequence = c.FocusedSeq("content",
    "content" / c.GreedyRange(
        c.FocusedSeq("valueonly",
            "terminator" / c.Peek(c.Byte),
            c.StopIf(c.this.terminator == 0),
            "valueonly" / ValueOnly,
        ),
    ),
    c.Const(b'\0'),
)

PSBTKeyless = c.Struct(
    "magic" / c.Const(b'psbt'),
    "sep" / c.Const(b'\xff'),
    "general" / ValueSequence,
    "transaction" / c.RestreamData(c.this.general[0].value, Transaction),
    "inputs" / c.Array(c.len_(c.this.transaction.inputs), ValueSequence),
    "outputs" / c.Array(c.len_(c.this.transaction.outputs), ValueSequence),
    c.Terminated,
)

# micro-parser for BIP32

BIP32Derivation = c.Struct(
    "fingerprint" / c.Bytes(4),
    "path" / c.GreedyRange(c.Int32ul),
)


def to_protobuf(psbt):
    """Make a protobuf message from a parsed Key-Value psbt"""
    # construct a protobuf repr now
    msg = bip174.PSBT(unsigned_transaction=psbt.general[0].value)

    for inp in psbt.inputs:
        in_msg = bip174.InputType()
        for entry in inp:
            if entry.key.type == 0:
                in_msg.non_witness_utxo = entry.value
            elif entry.key.type == 1:
                in_msg.witness_utxo = entry.value
            elif entry.key.type == 2:
                in_msg.partial_signature = bip174.PartialSignature(public_key=entry.key.data, signature=entry.value)
            elif entry.key.type == 3:
                in_msg.sighash_type = int.from_bytes(entry.value, "little")
            elif entry.key.type == 4:
                in_msg.redeem_script = entry.value
            elif entry.key.type == 5:
                in_msg.witness_script = entry.value
            elif entry.key.type == 6:
                bip32 = BIP32Derivation.parse(entry.value)
                print("found path", 'm/' + '/'.join((str(i & ~HARDENED_FLAG) + "'") if i & HARDENED_FLAG else str(i) for i in bip32.path))
                in_msg.bip32_path.append(bip174.BIP32Derivation(master_pubkey=bip32.fingerprint, path=list(bip32.path)))
            elif entry.key.type == 7:
                in_msg.finalized_scriptsig = entry.value
            elif entry.key.type == 8:
                in_msg.finalized_scriptwitness = entry.value
        msg.inputs.append(in_msg)

    for outp in psbt.outputs:
        out_msg = bip174.OutputType()
        for entry in outp:
            if entry.key.type == 0:
                out_msg.redeem_script = entry.value
            elif entry.key.type == 1:
                out_msg.witness_script = entry.value
            elif entry.key.type == 2:
                bip32 = BIP32Derivation.parse(entry.value)
                print("found path", 'm/' + '/'.join((str(i & ~HARDENED_FLAG) + "'") if i & HARDENED_FLAG else str(i) for i in bip32.path))
                out_msg.bip32_path.append(bip174.BIP32Derivation(master_pubkey=bip32.fingerprint, path=list(bip32.path)))
        msg.outputs.append(out_msg)

    return msg


def to_keyless(psbt):
    """Make a keyless dict for building with PSBTKeyless from PSBT data"""
    keyless = dict(
        transaction=psbt.transaction,
        general=[dict(type=0, value=psbt.general[0].value)],
        inputs=[],
        outputs=[],
    )
    for inp in psbt.inputs:
        l = []
        for entry in inp:
            if entry.key.type == 2:
                value = entry.key.data + entry.value
            else:
                value = entry.value
            l.append(dict(type=entry.key.type, value=value))
        keyless["inputs"].append(l)

    for outp in psbt.outputs:
        l = [dict(type=entry.key.type, value=entry.value) for entry in outp]
        keyless["outputs"].append(l)

    return keyless


def read_tx():
    """Read hex value from stdin"""
    if os.isatty(sys.stdin.fileno()):
        tx_hex = input("Enter transaction in hex format: ")
    else:
        tx_hex = sys.stdin.read().strip()

    return binascii.unhexlify(tx_hex)


if __name__ == "__main__":
    psbt_bin = read_tx()
    psbt = PSBT.parse(psbt_bin)

    proto = to_protobuf(psbt)

    # protobuf dump
    buf = BytesIO()
    protobuf.dump_message(buf, proto)
    proto_dump = buf.getvalue()

    # readable data
    print("Transaction data:")
    print(psbt.transaction)
    print(protobuf.format_message(proto))

    # lengths
    print("length of PSBT: ", len(psbt_bin))
    print("protobuf length:", len(proto_dump) + 5)  # because the 5-byte leading magic is not included

    # generate keyless version
    keyless = to_keyless(psbt)
    keyless_bin = PSBTKeyless.build(keyless)

    print("length of keyless:", len(keyless_bin))
