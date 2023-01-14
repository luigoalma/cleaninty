from struct import pack, unpack
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as crypto_padding
from cryptography.hazmat.primitives import hashes

from .constants import _load_cfg_rsa_keys, _cfg_pubnums
from .otp import OTP
from .exception import ClassInitError, DataProcessingError

__all__ = [
	"LFCS"
]

_load_cfg_rsa_keys()

class LFCS:
	def __init__(self, data: typing.SupportsBytes):
		self._lfcs_data = bytes(data)[:0x110]

		if len(self._lfcs_data) != 0x110:
			raise ClassInitError("LFCS data should be 272 bytes")

		segments = unpack("<256s8sQ", self._lfcs_data)

		self._sign_block = segments[0]
		self._upper_data = self._lfcs_data[0x100:]

		if segments[1][0] + sum(segments[1][2:]) != 0:
			raise ClassInitError("LFCS bytes @ 0x100 to 0x107, excluding 0x101, not supported as non 0")

		if 0 != segments[1][1] != 1:
			raise ClassInitError("LFCS byte @ 0x101 expected to be 0 or 1")

		self._is_dev = bool(segments[1][1])
		self._lfcs_id = segments[2]

		try:
			key = _cfg_pubnums['LFCS_DEV'] if self._is_dev else _cfg_pubnums['LFCS_RETAIL']

			if key is None:
				_load_cfg_rsa_keys()
				key = _cfg_pubnums['LFCS_DEV'] if self._is_dev else _cfg_pubnums['LFCS_RETAIL']

			key = key.public_key(default_backend())
			key.verify(self._sign_block, self._upper_data, crypto_padding.PKCS1v15(), hashes.SHA256())
			self._is_signed = True
		except Exception as e:
			self._is_signed = False

	def __bytes__(self):
		return self._lfcs_data

	def __len__(self):
		return len(self._lfcs_data)

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} is_signed={self._is_signed!r} is_dev={self._is_dev!r} lfcs_id={self._lfcs_id!r}>"

	@classmethod
	def generate_from_otp(cls, otp: OTP) -> 'LFCS':
		if not isinstance(otp, OTP):
			raise DataProcessingError("Expected OTP")

		lfcs = pack("<256xxB6xQ", 1 if otp.is_dev else 0, otp.lfcs_id)

		return cls(lfcs)

	@property
	def is_signed(self) -> bool:
		return self._is_signed

	@property
	def is_dev(self) -> bool:
		return self._is_dev

	@property
	def lfcs_id(self) -> int:
		return self._lfcs_id
