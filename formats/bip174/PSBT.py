# Automatically generated by pb2py
from .. import protobuf as p
if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None
from .InputType import InputType
from .OutputType import OutputType


class PSBT(p.MessageType):
    FIELDS = {
        1: ('unsigned_transaction', p.BytesType, 0),
        2: ('inputs', InputType, p.FLAG_REPEATED),
        3: ('outputs', OutputType, p.FLAG_REPEATED),
    }

    def __init__(
        self,
        unsigned_transaction: bytes = None,
        inputs: List[InputType] = None,
        outputs: List[OutputType] = None
    ) -> None:
        self.unsigned_transaction = unsigned_transaction
        self.inputs = inputs if inputs is not None else []
        self.outputs = outputs if outputs is not None else []