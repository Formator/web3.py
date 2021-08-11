from __future__ import (
    absolute_import,
)

from eth_keys.datatypes import (  # noqa: F401
    BaseSignature,
    NonRecoverableSignature,
    PrivateKey,
    PublicKey,
    Signature,
)
from eth_keys.exceptions import (
    BadSignature,
)
from eth_keys.utils import (
    der,
)
from eth_keys.utils.numeric import (
    coerce_low_s,
)
from eth_keys.validation import (
    validate_uncompressed_public_key_bytes,
)
from eth_utils import (
    big_endian_to_int,
)
from typing import (  # noqa: F401
    Optional,
)

from .base import (
    BaseECCBackend,
)
from .coincurve import (
    CoinCurveECCBackend,
)


class TolarCurveBackend(CoinCurveECCBackend):
    def private_key_to_public_key(self, private_key: PrivateKey) -> PublicKey:
        public_key_bytes = self.keys.PrivateKey(private_key.to_bytes()).public_key.format(
            compressed=False,
        )[1:]
        return PublicKey(public_key_bytes, backend=self)

    def decompress_public_key_bytes(self,
                                    compressed_public_key_bytes: bytes) -> bytes:
        public_key = self.keys.PublicKey(compressed_public_key_bytes)
        return public_key.format(compressed=False)[1:]

    def compress_public_key_bytes(self,
                                  uncompressed_public_key_bytes: bytes) -> bytes:
        validate_uncompressed_public_key_bytes(uncompressed_public_key_bytes)
        point = (
            big_endian_to_int(uncompressed_public_key_bytes[:32]),
            big_endian_to_int(uncompressed_public_key_bytes[32:]),
        )
        public_key = self.keys.PublicKey.from_point(*point)
        return public_key.format(compressed=True)
