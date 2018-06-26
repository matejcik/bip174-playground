import construct as c

CompactUintStruct = c.Struct(
    "base" / c.Int8ul,
    "ext" / c.Switch(c.this.base, {0xfd: c.Int16ul, 0xfe: c.Int32ul, 0xff: c.Int64ul}),
)


class CompactUintAdapter(c.Adapter):
    def _encode(self, obj, context, path):
        if obj < 0xfd:
            return {"base": obj, "ext": None}
        if obj < 2 ** 16:
            return {"base": 0xfd, "ext": obj}
        if obj < 2 ** 32:
            return {"base": 0xfe, "ext": obj}
        if obj < 2 ** 64:
            return {"base": 0xff, "ext": obj}
        raise ValueError("Value too big for compact uint")

    def _decode(self, obj, context, path):
        return obj["ext"] or obj["base"]


CompactUint = CompactUintAdapter(CompactUintStruct)
