from struct import pack, unpack
import hashlib, typing, datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from . import certificate
from ..common import digitalsignature as digsign
from .exception import ClassInitError

__all__ = [
	"OTP",
	"NGCert"
]

class OTP:
	def __init__(self, data: typing.SupportsBytes):
		data = bytes(data)[:0x400]
		orig_data = data

		if len(data) != 0x400:
			raise ClassInitError("Need 1024 bytes for full OTP")

		segments = unpack(">128xI408xI30s2x64xIII60s312x", data)

		self._otp_data = data

		self._fuse_type = segments[0]
		self._wiiu_device_id = segments[1]
		self._ng_cert_privk = int.from_bytes(segments[2], 'big') & ((1 << 233) - 1)
		self._ng_cert_ms_id = segments[3]
		self._ng_cert_ca_id = segments[4]
		self._ng_cert_expiration = segments[5]
		self._ng_cert_signature = segments[6]

		# TODO: parse everything else

	def __bytes__(self):
		return self._otp_data

	def __len__(self):
		return len(self._otp_data)

	@property
	def fuse_type(self) -> int:
		return self._fuse_type

	@property
	def wiiu_device_id(self) -> int:
		return self._wiiu_device_id

	@property
	def ng_cert_privk(self) -> int:
		return self._ng_cert_privk

	@property
	def ng_cert_ms_id(self) -> int:
		return self._ng_cert_ms_id

	@property
	def ng_cert_ca_id(self) -> int:
		return self._ng_cert_ca_id

	@property
	def ng_cert_expiration_timestamp(self) -> int:
		return self._ng_cert_expiration

	@property
	def ng_cert_expiration(self) -> datetime.datetime:
		return datetime.datetime.fromtimestamp(self._ng_cert_expiration, datetime.UTC)

	@property
	def ng_cert_issuing_date(self) -> datetime.datetime:
		return self.ng_cert_expiration - datetime.timedelta(days=365*20)

	@property
	def ng_cert_signature(self) -> bytes:
		return self._ng_cert_signature

class NGCert(certificate.Certificate):
	def __init__(self, otp: OTP):
		if not isinstance(otp, OTP):
			raise ClassInitError("NGCert excepts OTP object")

		try:
			privkey = ec.derive_private_key(otp.ng_cert_privk, ec.SECT233R1(), default_backend())
			pubkeynumbers = privkey.public_key().public_numbers()
		except Exception as e:
			raise ClassInitError("EC Key derivation error") from e

		try:
			data = pack(
				">I60s64x64sI64sI30s30s60x",
				digsign.SignatureType.ECC_SHA256 if (otp.fuse_type & 0x18000000) == 0x10000000 else digsign.SignatureType.ECC_SHA1,
				otp.ng_cert_signature,
				f"Root-CA{otp.ng_cert_ca_id:08x}-MS{otp.ng_cert_ms_id:08x}".encode(),
				digsign.KeyType.ECC,
				f"NG{otp.wiiu_device_id:08x}".encode(),
				otp.ng_cert_expiration_timestamp,
				pubkeynumbers.x.to_bytes(30, 'big'),
				pubkeynumbers.y.to_bytes(30, 'big'),
			)
		except Exception as e:
			raise ClassInitError("Packing error") from e

		super().__init__(data)

		self._is_dev = otp.ng_cert_ca_id != 0x3 and otp.ng_cert_ms_id != 0x12 # I dont expect other values for prod
		self._device_id = otp.wiiu_device_id

		# TODO: create constants for cafe to then load and check like in the ctr side of cleaninty

		if not self.set_private_key(privkey.private_numbers()):
			raise ClassInitError("NGCert private key was not successfully loaded!")

	@property
	def is_dev(self) -> bool:
		return self._is_dev

	@property
	def is_retail(self) -> bool:
		return not self._is_dev

	@property
	def device_id(self) -> int:
		return self._device_id
