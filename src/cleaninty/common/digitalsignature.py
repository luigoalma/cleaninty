from enum import IntEnum, unique
from struct import pack, unpack
import typing

from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils, padding as crypto_padding
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature as crypto_InvalidSignature

from ..exception import CleanintyExceptionBase, ClassInitError

__all__ = [
	"DigitalSignature",
	"SignatureType",
	"KeyType",
	"InvalidSignatureError",
	"SignatureProcessingError",
	"SignatureTypeError",
	"VerificationError",
	"IssuingError",
	"KeyTypeError"
]

_PubkeysType = typing.Union[
	ec.EllipticCurvePublicKey,
	ec.EllipticCurvePublicKeyWithSerialization,
	rsa.RSAPublicKey,
	rsa.RSAPublicKeyWithSerialization
]

_PrivkeysType = typing.Union[
	ec.EllipticCurvePrivateKey,
	ec.EllipticCurvePrivateKeyWithSerialization,
	rsa.RSAPrivateKey,
	rsa.RSAPrivateKeyWithSerialization
]

class InvalidSignatureError(CleanintyExceptionBase):
	"""General DigitalSignature invalid signature exception"""

class SignatureProcessingError(CleanintyExceptionBase):
	"""General DigitalSignature signature check exception"""

class SignatureTypeError(CleanintyExceptionBase):
	"""General SignatureType exception"""

class VerificationError(CleanintyExceptionBase):
	"""General IssuedObject verification exception"""

class IssuingError(CleanintyExceptionBase):
	"""General IssuedObject reissuing exception"""

class KeyTypeError(CleanintyExceptionBase):
	"""General KeyType exception"""

@unique
class SignatureType(IntEnum):
	RSA_4096_SHA1   = 0x10000
	RSA_2048_SHA1   = 0x10001
	ECC_SHA1        = 0x10002
	RSA_4096_SHA256 = 0x10003
	RSA_2048_SHA256 = 0x10004
	ECC_SHA256      = 0x10005

	@classmethod
	def is_valid(cls, entry: typing.Union['SignatureType', int]) -> bool:
		value = int(entry)
		return value >= cls.RSA_4096_SHA1 and value <= cls.ECC_SHA256

	@classmethod
	def sign_block_size(cls, entry: typing.Union['SignatureType', int]) -> int:
		value = int(entry)
		if value == cls.RSA_4096_SHA1 or value == cls.RSA_4096_SHA256:
			return 0x200
		if value == cls.RSA_2048_SHA1 or value == cls.RSA_2048_SHA256:
			return 0x100
		if value == cls.ECC_SHA1 or value == cls.ECC_SHA256:
			return 0x3C
		raise SignatureTypeError("Invalid SignatureType")

	@classmethod
	def sign_padding_block_size(cls, entry: typing.Union['SignatureType', int]) -> int:
		value = int(entry)
		if value == cls.RSA_4096_SHA1 or value == cls.RSA_4096_SHA256 or value == cls.RSA_2048_SHA1 or value == cls.RSA_2048_SHA256:
			return 0x3C
		if value == cls.ECC_SHA1 or value == cls.ECC_SHA256:
			return 0x40
		raise SignatureTypeError("Invalid SignatureType")

	@classmethod
	def hash_algo(cls, entry: typing.Union['SignatureType', int]) -> hashes.HashAlgorithm:
		value = int(entry)
		if value == cls.RSA_4096_SHA1 or value == cls.RSA_2048_SHA1 or value == cls.ECC_SHA1:
			return hashes.SHA1
		if value == cls.RSA_4096_SHA256 or value == cls.RSA_2048_SHA256 or value == cls.ECC_SHA256:
			return hashes.SHA256
		raise SignatureTypeError("Invalid SignatureType")

@unique
class KeyType(IntEnum):
	RSA_4096 = 0
	RSA_2048 = 1
	ECC      = 2

	@classmethod
	def is_valid(cls, entry: typing.Union['KeyType', int]) -> bool:
		value = int(entry)
		return value >= cls.RSA_4096 and value <= cls.ECC

	@classmethod
	def does_verify_digital_sign_type(
		cls,
		certtype: typing.Union['KeyType', int],
		digsigntype: typing.Union[SignatureType, int]
	) -> bool:
		certtype = cls(certtype)
		digsigntype = SignatureType(digsigntype)
		if (digsigntype == SignatureType.RSA_4096_SHA1 or digsigntype == SignatureType.RSA_4096_SHA256) and certtype == cls.RSA_4096:
			return True
		if (digsigntype == SignatureType.RSA_2048_SHA1 or digsigntype == SignatureType.RSA_2048_SHA256) and certtype == cls.RSA_2048:
			return True
		if (digsigntype == SignatureType.ECC_SHA1 or digsigntype == SignatureType.ECC_SHA256) and certtype == cls.ECC:
			return True
		return False

class DigitalSignature:
	def __init__(self, data: typing.SupportsBytes):
		self._sign_type = unpack(">I", bytes(data)[:4])[0]

		if not SignatureType.is_valid(self._sign_type):
			raise ClassInitError("Invalid signature type")

		block_size = SignatureType.sign_block_size(self._sign_type)

		self._sign_block = bytes(data[4:block_size+4])

		if len(self._sign_block) != block_size:
			raise ClassInitError("Not enough data to get the full block size")

	def __bytes__(self):
		block_size = SignatureType.sign_block_size(self._sign_type)
		pad_size = SignatureType.sign_padding_block_size(self._sign_type)

		return pack(f">I{block_size}s{pad_size}x", self._sign_type, self._sign_block)

	def __len__(self):
		block_size = SignatureType.sign_block_size(self._sign_type)
		pad_size = SignatureType.sign_padding_block_size(self._sign_type)
		return 4 + block_size + pad_size

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		sigtype = SignatureType(self._sign_type)
		return f"<{modname}.{clsname} sign_type={repr(sigtype)}>"

	@property
	def sign_type(self) -> SignatureType:
		return SignatureType(self._sign_type)

	@property
	def raw_sign_block(self) -> bytes:
		return self._sign_block

	@property
	def encoded_signature(self) -> bytes:
		block_size = SignatureType.sign_block_size(self._sign_type)

		if block_size == 0x3C:
			r, s = unpack("30s30s", self._sign_block)
			r = int(r.hex(), 16)
			s = int(s.hex(), 16)
			return crypto_utils.encode_dss_signature(r, s)

		return self.raw_sign_block

	@property
	def hash_algo(self) -> hashes.HashAlgorithm:
		return SignatureType.hash_algo(self._sign_type)

	def _pubkey_validate(
		self,
		key: _PubkeysType
	) -> typing.Optional[_PubkeysType]:
		block_size = SignatureType.sign_block_size(self._sign_type)

		if block_size == 0x3C:
			if isinstance(key, ec.EllipticCurvePrivateKeyWithSerialization) or isinstance(key, ec.EllipticCurvePrivateKey):
				return key.public_key()
			if isinstance(key, ec.EllipticCurvePublicKeyWithSerialization) or isinstance(key, ec.EllipticCurvePublicKey):
				return key
			return None

		if isinstance(key, rsa.RSAPrivateKeyWithSerialization) or isinstance(key, rsa.RSAPrivateKey):
			return key.public_key()
		if isinstance(key, rsa.RSAPublicKeyWithSerialization) or isinstance(key, rsa.RSAPublicKey):
			return key
		return None

	def _privkey_validate(
		self,
		key: _PrivkeysType,
		signtype: typing.Union[SignatureType, int]
	) -> typing.Optional[_PrivkeysType]:
		block_size = SignatureType.sign_block_size(signtype)

		if block_size == 0x3C:
			if isinstance(key, ec.EllipticCurvePrivateKeyWithSerialization) or isinstance(key, ec.EllipticCurvePrivateKey):
				return key
			return None

		if isinstance(key, rsa.RSAPrivateKeyWithSerialization) or isinstance(key, rsa.RSAPrivateKey):
			return key
		return None

	def verify_data(
		self,
		key: _PubkeysType,
		data: typing.SupportsBytes
	) -> None:
		try:
			hashalgo = self.hash_algo()

			key = self._pubkey_validate(key)

			if SignatureType.sign_block_size(self._sign_type) == 0x3C:
				key.verify(self.encoded_signature, data, ec.ECDSA(hashalgo))
			else:
				key.verify(self.encoded_signature, data, crypto_padding.PKCS1v15(), hashalgo)

		except crypto_InvalidSignature as e:
			raise InvalidSignatureError("Invalid Signature") from e
		except (TypeError, AttributeError) as e:
			raise SignatureProcessingError("Unexpected exception or invalid key object") from e
		except Exception as e:
			raise SignatureProcessingError("Unexpected exception") from e

	def verify_digest(
		self,
		key: _PubkeysType,
		digest: typing.SupportsBytes
	) -> None:
		try:
			hashalgo = self.hash_algo()

			key = self._pubkey_validate(key)

			if SignatureType.sign_block_size(self._sign_type) == 0x3C:
				key.verify(self.encoded_signature, digest, ec.ECDSA(crypto_utils.Prehashed(hashalgo)))
			else:
				key.verify(self.encoded_signature, digest, crypto_padding.PKCS1v15(), crypto_utils.Prehashed(hashalgo))

		except crypto_InvalidSignature as e:
			raise InvalidSignatureError("Invalid Signature") from e
		except (TypeError, AttributeError) as e:
			raise SignatureProcessingError("Unexpected exception or invalid key object") from e
		except Exception as e:
			raise SignatureProcessingError("Unexpected exception") from e

	def update_sign_with_data(
		self,
		signtype: typing.Union[SignatureType, int, None],
		key: _PrivkeysType,
		data: typing.SupportsBytes
	) -> None:
		try:
			if not signtype:
				signtype = self._sign_type

			hashalgo = SignatureType.hash_algo(signtype)

			key = self._privkey_validate(key, signtype)

			block_size = SignatureType.sign_block_size(signtype)

			if block_size == 0x3C:
				signature = key.sign(bytes(data), ec.ECDSA(hashalgo()))
				signature = crypto_utils.decode_dss_signature(signature)
				signature = pack("30s30s", signature[0].to_bytes(30, 'big'), signature[1].to_bytes(30, 'big'))
			else:
				signature = key.sign(bytes(data), crypto_padding.PKCS1v15(), hashalgo())

			if len(signature) != block_size:
				raise SignatureProcessingError("Key did not generate signature of proper length for requested signature type")

			self._sign_block = signature

		except (TypeError, AttributeError) as e:
			raise SignatureProcessingError("Unexpected exception or invalid key object") from e
		except SignatureProcessingError:
			raise
		except Exception as e:
			raise SignatureProcessingError("Unexpected exception") from e

	def update_sign_with_digest(
		self,
		signtype: typing.Union[SignatureType, int, None],
		key: _PrivkeysType,
		digest: typing.SupportsBytes
	) -> None:
		try:
			if not signtype:
				signtype = self._sign_type

			hashalgo = SignatureType.hash_algo(signtype)

			key = self._privkey_validate(key, signtype)

			block_size = SignatureType.sign_block_size(signtype)

			if block_size == 0x3C:
				signature = key.sign(bytes(digest), ec.ECDSA(crypto_utils.Prehashed(hashalgo())))
				signature = crypto_utils.decode_dss_signature(signature)
				signature = pack("30s30s", signature[0].to_bytes(30, 'big'), signature[1].to_bytes(30, 'big'))
			else:
				signature = key.sign(bytes(digest), crypto_padding.PKCS1v15(), crypto_utils.Prehashed(hashalgo()))

			if len(signature) != block_size:
				raise SignatureProcessingError("Key did not generate signature of proper length for requested signature type")

			self._sign_block = signature

		except (TypeError, AttributeError) as e:
			raise SignatureProcessingError("Unexpected exception or invalid key object") from e
		except SignatureProcessingError:
			raise
		except Exception as e:
			raise SignatureProcessingError("Unexpected exception") from e

class IssuingObject:
	def __init__(
		self,
		callable_get_key_type: typing.Callable[[], KeyType],
		callable_get_pub_key: typing.Callable[
			[],
			_PubkeysType
		],
		callable_get_priv_key: typing.Callable[
			[],
			typing.Optional[_PrivkeysType]
		],
		callable_get_issuing_name: typing.Callable[[], str]
	):
		self._issuer_cbs = {
			'key_type': callable_get_key_type,
			'pub_key': callable_get_pub_key,
			'priv_key': callable_get_priv_key,
			'issuing_name': callable_get_issuing_name
		}

class IssuedObject:
	def __init__(
		self,
		callable_get_data: typing.Callable[[], typing.SupportsBytes],
		callable_get_digital_sign: typing.Callable[[], DigitalSignature],
		callable_get_issuer: typing.Callable[[], str],
		callable_get_reissued_data: typing.Callable[[str], typing.SupportsBytes],
		callable_update: typing.Callable[[DigitalSignature, str, typing.SupportsBytes], None]
	):
		self._issued_cbs = {
			'data': callable_get_data,
			'sign': callable_get_digital_sign,
			'issuer': callable_get_issuer,
			'data_for_resign_reissue': callable_get_reissued_data,
			'update_reissued': callable_update
		}

	def verify(
		self,
		issuer_or_key: typing.Union[
			IssuingObject,
			_PubkeysType
		]
	) -> None:
		_sign = self._issued_cbs['sign']()
		if isinstance(issuer_or_key, IssuingObject):
			issuer = issuer_or_key

			if issuer._issuer_cbs['issuing_name']() != self._issued_cbs['issuer']():
				raise VerificationError("Given issuing object does not verify this issued object")

			if not KeyType.does_verify_digital_sign_type(issuer._issuer_cbs['key_type'](), _sign.sign_type):
				raise VerificationError("Given issuing object key type does not verify this issued object")

			key = issuer._issuer_cbs['pub_key']()
		else:
			key = issuer_or_key

		_sign.verify_data(key, self._issued_cbs['data']())

	def reissue(
		self,
		issuer_or_key: typing.Union[
			IssuingObject,
			_PrivkeysType
		],
		signtype: typing.Union[SignatureType, int, None] = None,
		issuer: typing.Optional[str] = None
	) -> None:
		if isinstance(issuer_or_key, IssuingObject):
			issuer = issuer_or_key

			issuer_str = issuer._issuer_cbs['issuing_name']()

			key = issuer._issuer_cbs['priv_key']()
		else:
			key = issuer_or_key

			try:
				issuer_str = str(issuer_str) if issuer_str is not None else None
			except Exception as e:
				raise IssuingError("Issuer not string") from e

		if not key:
			raise IssuingError("Private key not available")

		if not issuer_str:
			raise IssuingError("No issuer name")

		if len(issuer_str) > 64:
			raise IssuingError("Issuer name too big, max 64")

		_new_data = self._issued_cbs['data_for_resign_reissue'](issuer_str)

		_sign_copy = DigitalSignature(bytes(self._issued_cbs['sign']()))
		_sign_copy.update_sign_with_data(signtype, key, _new_data)

		self._issued_cbs['update_reissued'](_sign_copy, issuer_str, _new_data)
