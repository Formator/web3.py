from collections.abc import (
    Mapping,
)
from cytoolz import (
    dissoc,
)
from eth_account import (
    Account,
)
from eth_account._utils.legacy_transactions import (
    Transaction,
    vrs_from,
)
from eth_account._utils.signing import (
    hash_of_signed_transaction,
    sign_message_hash,
    sign_transaction_dict,
    to_standard_signature_bytes,
    to_standard_v,
)
from eth_account._utils.typed_transactions import (
    TypedTransaction,
)
from eth_account.datastructures import (
    SignedMessage,
    SignedTransaction,
)
from eth_account.hdaccount import (
    ETHEREUM_DEFAULT_PATH,
    generate_mnemonic,
    key_from_seed,
    seed_from_mnemonic,
)
from eth_account.messages import (
    SignableMessage,
    _hash_eip191_message,
)
from eth_account.signers.local import (
    LocalAccount,
)
from eth_keyfile import (
    create_keyfile_json,
    decode_keyfile_json,
)
from eth_keys.exceptions import (
    ValidationError,
)
from eth_utils.conversions import (
    to_hex,
)
from eth_utils.curried import (
    combomethod,
    hexstr_if_str,
    is_dict,
    keccak,
    text_if_str,
    to_bytes,
    to_int,
)
from hexbytes import (
    HexBytes,
)
import json
import os
import warnings

from tol_keys import (
    KeyAPI,
    keys,
)


class TolarLocalAccount(LocalAccount):
    def eth_address_to_tolar_address(self, ethAddress:str) :
        from web3 import (
            Web3,
        )
        prefix = 'T'
        prefixHex = to_hex(text=prefix)[-2:]
        addressHash = Web3.solidityKeccak(['bytes'], [ethAddress])
        hashOfHash = Web3.solidityKeccak(['bytes'], [addressHash.hex()])
        tolarAddress =prefixHex +ethAddress[-2:] + hashOfHash.hex()[-1*(len(hashOfHash.hex()) - 8):]
        return tolarAddress.lower()

    def __init__(self, key, account):
        """
        Initialize a new account with the the given private key.

        :param eth_keys.PrivateKey key: to prefill in private key execution
        :param ~eth_account.account.Account account: the key-unaware management API
        """
        self._publicapi = account

        address = key.public_key.to_checksum_address()
        self._address = self.eth_address_to_tolar_address(address)

        key_raw = key.to_bytes()
        self._private_key = key_raw

        self._key_obj = key

        

class TolarAccount(Account):

    _keys = keys

    @combomethod
    def create(self, extra_entropy=''):
        extra_key_bytes = to_bytes(hexstr=extra_entropy)
        #key_bytes = keccak(os.urandom(32) + extra_key_bytes)
        
        address = self.from_key(extra_key_bytes)
        #key_bytes = keccak(extra_key_bytes)
        #address = self.from_key(key_bytes)
        # tol_address = self.eth_address_to_tolar_address(ethAddress=address)
        return address

    @combomethod
    def from_key(self, private_key):
        r"""
        Returns a convenient object for working with the given private key.

        :param private_key: The raw private key
        :type private_key: hex str, bytes, int or :class:`eth_keys.datatypes.PrivateKey`
        :return: object with methods for signing and encrypting
        :rtype: LocalAccount

        .. doctest:: python

            >>> acct = Account.from_key(
            ... 0xb25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364)
            >>> acct.address
            '0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E'
            >>> acct.key
            HexBytes('0xb25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364')

            # These methods are also available: sign_message(), sign_transaction(), encrypt()
            # They correspond to the same-named methods in Account.*
            # but without the private key argument
        """
        key = self._parsePrivateKey(private_key)
        local_address =  TolarLocalAccount(key, self)
        # tol_address = self.eth_address_to_tolar_address(ethAddress=local_address.address)
        return local_address

    @combomethod
    def _parsePrivateKey(self, key):
        """
        Generate a :class:`eth_keys.datatypes.PrivateKey` from the provided key.

        If the key is already of type :class:`eth_keys.datatypes.PrivateKey`, return the key.

        :param key: the private key from which a :class:`eth_keys.datatypes.PrivateKey`
                    will be generated
        :type key: hex str, bytes, int or :class:`eth_keys.datatypes.PrivateKey`
        :returns: the provided key represented as a :class:`eth_keys.datatypes.PrivateKey`
        """
        if isinstance(key, self._keys.PrivateKey):
            return key

        try:
            return self._keys.PrivateKey(HexBytes(key))
        except ValidationError as original_exception:
            raise ValueError(
                "The private key must be exactly 32 bytes long, instead of "
                "%d bytes." % len(key)
            ) from original_exception


