from struct import pack, unpack
import typing, hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, cmac
import cryptography.hazmat.primitives.ciphers as crypto_ciphers

from . import keys
from .lfcs import LFCS
from .otp import OTP
from .exception import ClassInitError, DataProcessingError
from .constants import _load_p9_keys, _p9_keys

__all__ = [
	"MovableSed"
]

_load_p9_keys()

class MovableSed:
	def __init__(self, data: typing.SupportsBytes):
		self._msed_data = bytes(data)[:0x140]

		if 0x120 != len(self._msed_data) != 0x140:
			raise ClassInitError("movable.sed should be 288 or 320 bytes")

		segments = unpack("<4s4B272sQ", self._msed_data[:0x120])

		if segments[0] != b'SEED':
			raise ClassInitError("movable.sed invalid start")

		if not (segments[1] == segments[3] == segments[4] == 0):
			# these should not have effects, but they still should be 0
			# asides not allowing non 0 if @ 0x5 is 0
			raise ClassInitError("movable.sed byte @ 0x4, 0x6 and 0x7 should be 0")

		if 0 != segments[2] != 1:
			raise ClassInitError("movable.sed unrecognized byte value @ 0x5, expected 0 or 1")

		self._lfcs = LFCS(segments[5])

		if segments[2] == 1 and len(self._msed_data) == 0x140:
			other_segments = unpack("<I12s16s", self._msed_data[0x120:])
			if sum(other_segments[1]) != 0:
				raise ClassInitError("movable.sed the 12 bytes @ 0x124 should be all 0")
			self._format_rng_increment = other_segments[0]
			self._cmac = other_segments[2]
		elif segments[2] == 1 and len(self._msed_data) == 0x120:
			segments = list(segments)
			segments[2] = 0
			segments = tuple(segments)
			self._msed_data = pack("<4s4B272sQ", *segments)
			self._format_rng_increment = None
			self._cmac = None
		else:
			self._format_rng_increment = None
			self._cmac = None

		self._high_u64 = segments[6]
		self._keyy = pack("<QQ", self._lfcs.lfcs_id, self._high_u64)

	def __bytes__(self):
		return self._msed_data

	def __len__(self):
		return len(self._msed_data)

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} lfcs={self._lfcs!r} high_u64={self._high_u64!r} keyy={self._keyy!r} format_rng_increment={self._format_rng_increment!r} cmac={self._cmac!r}>"

	@classmethod
	def generate_from_otp(cls, otp: OTP) -> 'MovableSed':
		if not isinstance(otp, OTP):
			raise DataProcessingError("Expected OTP")

		lfcs = LFCS.generate_from_otp(otp)

		msed = pack("<4s4x272sQ", b'SEED', bytes(lfcs), otp.supplementary_id)

		msed = cls(msed)
		msed.fixup_footer_data(otp)

		return msed

	@keys._ensure_b9(False)
	def fixup_footer_data(self, otp: OTP, dev: typing.Optional[bool] = None) -> bool:
		if not isinstance(otp, OTP):
			raise DataProcessingError("Expected OTP")

		if not otp.gen_console_keys():
			return False

		key = keys.scramble_keys(
			otp.console_keys_x[0xB],
			keys.get_b9_y(0xB, dev if dev is not None else otp.is_dev)
		).to_bytes(16, 'big')

		if key is None:
			return False

		format_rng_increment = 0
		if self._lfcs.lfcs_id == otp.lfcs_id:
			format_rng_increment = self._high_u64 - otp.supplementary_id
			format_rng_increment &= 0xFFFFFFFF

		msed = pack("<4sxB2x272sQI12x", b'SEED', 1, bytes(self._lfcs), self._high_u64, format_rng_increment)

		c = cmac.CMAC(crypto_ciphers.algorithms.AES(key), default_backend())
		c.update(hashlib.sha256(msed).digest())
		cmac_hash = c.finalize()

		msed += cmac_hash

		self._msed_data = msed
		self._format_rng_increment = format_rng_increment
		self._cmac = cmac_hash

		return True

	@keys._ensure_b9(False)
	def check_cmac(
		self,
		otp: OTP,
		dev: typing.Optional[bool] = None,
		fix: bool = False
	) -> typing.Optional[bool]:
		if self._cmac is None:
			if fix:
				return self.fixup_footer_data(otp, dev)
			return None

		if not isinstance(otp, OTP):
			raise DataProcessingError("Expected OTP")

		if not otp.gen_console_keys():
			return False

		key = keys.scramble_keys(
			otp.console_keys_x[0xB],
			keys.get_b9_y(0xB, dev if dev is not None else otp.is_dev)
		).to_bytes(16, 'big')

		if key is None:
			return False

		c = cmac.CMAC(crypto_ciphers.algorithms.AES(key), default_backend())
		c.update(hashlib.sha256(self._msed_data[:0x130]).digest())
		cmac_hash = c.finalize()

		if fix and self._cmac != cmac_hash:
			self._msed_data = self._msed_data[:0x130] + cmac_hash
			self._cmac = cmac_hash

		return self._cmac == cmac_hash

	@classmethod
	@keys._ensure_b9(None)
	def load_from_ivs(cls, ivs: typing.SupportsBytes, dev: bool) -> typing.Optional['MovableSed']:
		ivs = bytes(ivs)[:0x130]
		if len(ivs) != 0x130:
			return None

		keyx_0x35 = keys.get_b9_x(0x35, dev)

		keyy = _p9_keys['IVS_KEYY']
		cmackeyy = _p9_keys['IVS_CMAC_KEYY']
		if keyy is None or cmackeyy is None:
			_load_p9_keys()
			keyy = _p9_keys['IVS_KEYY']
			cmackeyy = _p9_keys['IVS_CMAC_KEYY']
			if keyy is None or cmackeyy is None:
				return None

		key = keys.scramble_keys(
			keyx_0x35,
			keyy
		).to_bytes(16, 'big')

		cmackey = keys.scramble_keys(
			keyx_0x35,
			cmackeyy
		).to_bytes(16, 'big')

		if key is None or cmackeyy is None:
			return None

		decryptor = crypto_ciphers.Cipher(
			crypto_ciphers.algorithms.AES(key),
			crypto_ciphers.modes.CBC(ivs[:0x10]),
			default_backend()
		).decryptor()
		msed = decryptor.update(ivs[0x10:]) + decryptor.finalize()

		c = cmac.CMAC(crypto_ciphers.algorithms.AES(cmackey), default_backend())
		c.update(hashlib.sha256(msed[:0x110]).digest())
		cmac_hash = c.finalize()

		if cmac_hash != ivs[:0x10]:
			return None

		return cls(msed)

	@keys._ensure_b9(None)
	def produce_ivs(self, dev: typing.Optional[bool] = None) -> typing.Optional[bytes]:
		keyx_0x35 = keys.get_b9_x(0x35, dev if dev is not None else self._lfcs.is_dev)

		keyy = _p9_keys['IVS_KEYY']
		cmackeyy = _p9_keys['IVS_CMAC_KEYY']
		if keyy is None or cmackeyy is None:
			_load_p9_keys()
			keyy = _p9_keys['IVS_KEYY']
			cmackeyy = _p9_keys['IVS_CMAC_KEYY']
			if keyy is None or cmackeyy is None:
				return None

		key = keys.scramble_keys(
			keyx_0x35,
			keyy
		).to_bytes(16, 'big')

		cmackey = keys.scramble_keys(
			keyx_0x35,
			cmackeyy
		).to_bytes(16, 'big')

		if key is None or cmackeyy is None:
			return None

		c = cmac.CMAC(crypto_ciphers.algorithms.AES(cmackey), default_backend())
		c.update(hashlib.sha256(self._msed_data[:0x110]).digest())
		cmac_hash = c.finalize()

		encryptor = crypto_ciphers.Cipher(
			crypto_ciphers.algorithms.AES(key),
			crypto_ciphers.modes.CBC(cmac_hash),
			default_backend()
		).encryptor()
		ivs_msed = encryptor.update(self._msed_data[:0x120]) + encryptor.finalize()

		return cmac_hash + ivs_msed

	@property
	def lfcs(self) -> LFCS:
		return self._lfcs

	@property
	def high_u64(self) -> int:
		return self._high_u64

	@property
	def keyy(self) -> bytes:
		return self._keyy

	@property
	def format_rng_increment(self) -> typing.Optional[int]:
		return self._format_rng_increment

	@property
	def cmac(self) -> typing.Optional[bytes]:
		return self._cmac
