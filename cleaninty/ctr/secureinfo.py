from struct import pack, unpack
import typing, re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as crypto_padding
from cryptography.hazmat.primitives import hashes

from .constants import _load_cfg_rsa_keys, _cfg_pubnums
from . import regionaldata
from .exception import ClassInitError

__all__ = [
	"SecureInfo"
]

_load_cfg_rsa_keys()

class SecureInfo:
	def __init__(self, data: typing.SupportsBytes, is_dev: typing.Optional[bool] = None):
		self._secinfo_data = bytes(data)[:0x111]

		try:
			segments = unpack(">256sBB15s", self._secinfo_data)
		except Exception as e:
			raise ClassInitError("Unpack error") from e

		self._upper_data = self._secinfo_data[0x100:]

		self._sign_block = segments[0]
		self._region = segments[1]
		self._unk_0x101 = segments[2]
		self._serial = segments[3].decode('ascii','replace').split('\x00', 1)[0]

		if not len(self._serial):
			raise ClassInitError("No serial number")

		if not self.validate_serial(self._serial):
			raise ClassInitError("Serial number could not be validated")

		self._is_signed = False
		self._is_dev = False

		if is_dev is not None:
			self._is_dev = bool(is_dev)

			try:
				key = _cfg_pubnums['SECINFO_DEV'] if is_dev else _cfg_pubnums['SECINFO_RETAIL']

				if key is None:
					_load_cfg_rsa_keys()
					key = _cfg_pubnums['SECINFO_DEV'] if is_dev else _cfg_pubnums['SECINFO_RETAIL']

				key = key.public_key(default_backend())
				key.verify(self._sign_block, self._upper_data, crypto_padding.PKCS1v15(), hashes.SHA256())
				self._is_signed = True
			except Exception:
				pass
		else:
			for i, key in enumerate(['SECINFO_RETAIL', 'SECINFO_DEV']):
				try:
					key = _cfg_pubnums[key]

					if key is None:
						_load_cfg_rsa_keys()
						key = _cfg_pubnums[key]

					key = key.public_key(default_backend())
					key.verify(self._sign_block, self._upper_data, crypto_padding.PKCS1v15(), hashes.SHA256())
					self._is_signed = True
					self._is_dev = bool(i)
					break
				except Exception:
					pass

	def __bytes__(self):
		return self._secinfo_data

	def __len__(self):
		return len(self._secinfo_data)

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		if not self.is_signed:
			return f"<{modname}.{clsname} is_signed={self.is_signed} region_str={self.region_str} unk_0x101={self.unk_0x101} serial={self.serial}>"
		else:
			return f"<{modname}.{clsname} is_signed={self.is_signed} is_dev={self.is_dev} region_str={self.region_str} unk_0x101={self.unk_0x101} serial={self.serial}>"

	@staticmethod
	def validate_serial(serial: str) -> typing.Optional[str]:
		try:
			match = re.fullmatch(r'^((?:[A-Z]{2,3})([0-9]{8}))([0-9])?$', serial.upper())
			if not match:
				return None

			sn = match.group(1)
			digits = [int(i) for i in match.group(2)]
			check_digit = match.group(3)
			check_digit = int(check_digit) if check_digit is not None else None
		except:
			return None

		if check_digit is None:
			return sn

		odd_group_sum = sum(digits[::2])
		even_group_sum = sum(digits[1::2])

		calc_step = ((3 * even_group_sum) + odd_group_sum) % 10
		calc_digit = (10 - calc_step) if calc_step != 0 else 0

		if check_digit != calc_digit:
			return None

		return sn

	@classmethod
	def create_from_serial_number(
		cls,
		serial: str,
		region: regionaldata.RegionType,
		is_dev: typing.Optional[bool] = None
	) -> typing.Optional['SecureInfo']:
		serial = cls.validate_serial(str(serial))
		region = regionaldata.Region.get_region(region)
		if not serial or region is None:
			return None

		return cls(pack('>256xBx15s', int(region), serial.encode()), is_dev)

	@property
	def region(self) -> int:
		return self._region
	
	@property
	def unk_0x101(self) -> int:
		return self._unk_0x101

	@property
	def serial(self) -> str:
		return self._serial

	@property
	def region_str(self) -> typing.Union[str, None]:
		return regionaldata.Region.get_region_str(self._region)

	@property
	def is_signed(self) -> bool:
		"""Check this before is_dev or is_retail, cannot guarantee either if not signed"""
		return self._is_signed

	@property
	def is_dev(self) -> bool:
		return self._is_dev

	@property
	def is_retail(self) -> bool:
		return not self._is_dev
