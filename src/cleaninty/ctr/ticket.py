from struct import unpack
import typing, hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..common import digitalsignature as digsign
from .exception import CTRExceptionBase, ClassInitError, DataProcessingError
from .otp import CTCert

__all__ = [
	"Ticket"
]

class Ticket(digsign.IssuedObject):
	def __init__(
		self,
		data: typing.SupportsBytes,
		device_cert: typing.Optional[CTCert] = None,
		act_first_import: bool = True # else False, act as a post-import raw dump
	):
		mindata = bytes(data)[:0x3B8]

		self._sign = digsign.DigitalSignature(mindata)

		mindata = mindata[len(self._sign):]

		if len(mindata) < 0x178: # 0x178 is minimal ticket block size
			raise ClassInitError("Not enough data for minimal ticket size")

		segments = unpack(">64s 60s BBB 16s c QIQ 2s H 8s B B 42s I c B 66s 64s 20s", mindata[:0x178])

		self._issuer_str = segments[0].decode('ascii','replace').split('\x00', 1)[0]
		self._ec_pubkey = segments[1]
		self._version = segments[2]
		self._ca_crl_version = segments[3]
		self._signed_crl_version = segments[4]
		self._enc_title_key = segments[5]
		self._reserved1 = segments[6]
		self._ticket_id = segments[7]
		self._device_id = segments[8]
		self._title_id = segments[9]
		self._reserved2 = segments[10]
		self._tik_title_version = segments[11]
		self._reserved3 = segments[12]
		self._license_type = segments[13]
		self._common_index = segments[14]
		self._reserved4 = segments[15]
		self._eshop_id = segments[16]
		self._reserved5 = segments[17]
		self._audit = segments[18]
		self._reserved6 = segments[19]
		self._limits = segments[20]
		self._content_index_header = unpack(">4s II 8s", segments[21])

		if not len(self._issuer_str):
			raise ClassInitError("No ticket issuer")

		if self._issuer_str.find('\uFFFD') != -1:
			raise ClassInitError("Invalid ticket issuer")

		if self._version != 1:
			raise ClassInitError("Unexpected ticket version")

		if self._content_index_header[0] != b'\x00\x01\x00\x14' or \
			self._content_index_header[3] != b'\x00\x01\x00\x14\x00\x00\x00\x00':
			raise ClassInitError("Invalid or unsupported content index")

		if self._content_index_header[1] < 20:
			raise ClassInitError("Invalid content index size")

		self._tik_block_size = 0x164 + self._content_index_header[1]
		self._tik_block = bytes(data)[len(self._sign):len(self._sign) + self._tik_block_size]

		if len(self._tik_block) < self._tik_block_size:
			raise ClassInitError("Insuffient data for full ticket")

		if self._content_index_header[2] < 20 or \
			self._content_index_header[2] < self._content_index_header[1] < self._content_index_header[2] + 20:
			raise ClassInitError("Invalid content index data header")

		if self._content_index_header[1] >= self._content_index_header[2] + 20:
			rights = 0
			data_header_off = 0x164 + self._content_index_header[2]
			data_header = unpack(
				">IIIIH2s",
				self._tik_block[
					data_header_off : data_header_off + 20
				]
			)
			if data_header[4] == 3 and data_header[1] != 0:
				data_off = 0x164 + data_header[0]
				data_off_max = self._tik_block_size
				data_off_end = data_off + data_header[1] * 0x84
				data_off_end = data_off_end if data_off_end < data_off_max else data_off_max
				count = (data_off_end - data_off) // 0x84
				if count <= 0:
					rights = (1 << 256) - 1
				else:
					rights = 0
					last_highest_index = 0
					for i in range(0, count):
						blk_index, blk_rights = unpack(
							">2x H 128s",
							self._tik_block[data_off+0x84*i:data_off+0x84*i+0x84]
						)
						foo = max(last_highest_index - blk_index, 0)
						if foo >= 1024:
							continue
						last_highest_index = max(last_highest_index, blk_index)
						right_block = int.from_bytes(blk_rights, 'little')
						right_block >>= foo
						right_block <<= foo + blk_index
						rights |= right_block
					rights &= (1 << 65536) - 1
			else:
				rights = (1 << 256) - 1

			self._rights = rights
		else:
			self._rights = (1 << 256) - 1 # default rights if not specified

		if device_cert is not None:
			self.fix_and_get_personal_key_tik(device_cert, act_first_import)
		else:
			self._personal_enc_title_key = None

		super().__init__(
			lambda: self._tik_block,
			lambda: self._sign,
			lambda: self.issuer,
			lambda issuer: issuer.ljust(64,'\x00').encode() + self._tik_block[0x40:],
			self._set_reissued
		)

	def __bytes__(self):
		return bytes(self._sign) + self._tik_block

	def __len__(self):
		return len(self._sign) + self._tik_block_size

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} issuer={self.issuer} ticket_id={self.ticket_id} device_id={self.device_id} title_id=0x{self.title_id:016x} eshop_id={self.eshop_id}>"

	def _set_reissued(self, sign: digsign.DigitalSignature, issuer: str, data: typing.SupportsBytes) -> None:
		self._sign = sign
		self._issuer_str = issuer
		self._tik_block = bytes(data)

	@staticmethod
	def _get_personal_tik_key_layer_key_iv(
		tik_id: typing.SupportsInt,
		ec_pubkey_block: typing.SupportsBytes,
		ct_certificate: CTCert
	) -> typing.Tuple[bytes, bytes]:
		if not isinstance(ct_certificate, CTCert):
			raise DataProcessingError("Expected CTCert")

		ct_ec_prikkey = ct_certificate.private_key()
		tik_id = int(tik_id) & ((1 << 64) - 1)
		ec_pubkey_block = bytes(ec_pubkey_block)

		if not ct_ec_prikkey or \
			(not isinstance(ct_ec_prikkey, ec.EllipticCurvePrivateKey) and not isinstance(ct_ec_prikkey, ec.EllipticCurvePrivateKeyWithSerialization)):
			raise DataProcessingError("Invalid ctcert ec key")

		if len(ec_pubkey_block) != 60:
			raise DataProcessingError("Expected 60 byte ec pubkey block")

		x, y = unpack("30s30s", ec_pubkey_block)
		x = int(x.hex(), 16) & ((1 << 233) - 1)
		y = int(y.hex(), 16) & ((1 << 233) - 1)
		tik_pubkey = ec.EllipticCurvePublicNumbers(x, y, ec.SECT233R1()).public_key(default_backend())

		aes_key = hashlib.sha1(ct_ec_prikkey.exchange(ec.ECDH(), tik_pubkey)).digest()[:16]
		iv = (tik_id << 64).to_bytes(16, 'big')

		return (aes_key, iv)

	# because one encryption layer was not enough appearantly
	@classmethod
	def _decrypt_personal_tik_key_layer(
		cls,
		enc_enc_title_key: typing.SupportsBytes,
		tik_id: typing.SupportsInt,
		ec_pubkey_block: typing.SupportsBytes,
		ct_certificate: CTCert
	) -> bytes:
		aes_key, iv = cls._get_personal_tik_key_layer_key_iv(tik_id, ec_pubkey_block, ct_certificate)

		enc_enc_title_key = bytes(enc_enc_title_key)

		if len(enc_enc_title_key) != 16:
			raise DataProcessingError("Expected 16 byte encrypted key")

		cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
		decryptor = cipher.decryptor()
		return decryptor.update(enc_enc_title_key) + decryptor.finalize()

	@classmethod
	def _encrypt_personal_tik_key_layer(
		cls,
		dec_enc_title_key: typing.SupportsBytes,
		tik_id: typing.SupportsInt,
		ec_pubkey_block: typing.SupportsBytes,
		ct_certificate: CTCert
	) -> bytes:
		aes_key, iv = cls._get_personal_tik_key_layer_key_iv(tik_id, ec_pubkey_block, ct_certificate)

		dec_enc_title_key = bytes(dec_enc_title_key)

		if len(dec_enc_title_key) != 16:
			raise DataProcessingError("Expected 16 byte decrypted key")

		cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
		encryptor = cipher.encryptor()
		return encryptor.update(dec_enc_title_key) + encryptor.finalize()

	@property
	def issuer(self) -> str:
		return self._issuer_str

	@property
	def ec_pubkey(self) -> bytes:
		return self._ec_pubkey

	@property
	def version(self) -> int:
		return self._version

	@property
	def ca_crl_version(self) -> int:
		return self._ca_crl_version

	@property
	def signed_crl_version(self) -> int:
		return self._signed_crl_version

	@property
	def enc_title_key(self) -> bytes:
		return self._enc_title_key

	@property
	def personal_enc_title_key(self) -> typing.Optional[bytes]:
		return self._personal_enc_title_key

	@property
	def ticket_id(self) -> int:
		return self._ticket_id

	@property
	def device_id(self) -> int:
		return self._device_id

	@property
	def title_id(self) -> int:
		return self._title_id

	@property
	def ticket_title_version(self) -> int:
		return self._tik_title_version

	@property
	def license_type(self) -> int:
		return self._license_type

	@property
	def common_index(self) -> int:
		return self._common_index

	@property
	def eshop_id(self) -> int:
		return self._eshop_id

	@property
	def audit(self) -> int:
		return self._audit

	@property
	def limits(self) -> bytes:
		return self._limits

	@property
	def ticket_block(self) -> bytes:
		return self._tik_block

	@property
	def is_personal(self) -> bool:
		return self._device_id != 0

	@property
	def installable_export(self) -> bytes:
		if not self.is_personal:
			return bytes(self)
		elif self._personal_enc_title_key is None or len(self._personal_enc_title_key) != 16:
			raise DataProcessingError("Missing personal encrypted key!")
		return bytes(self._sign) + self._tik_block[:0x7F] + self._personal_enc_title_key + self._tik_block[0x8F:]

	def fix_and_get_personal_key_tik(
		self,
		device_cert: CTCert,
		act_first_import: bool = True # else False, act as a post-import raw dump
	) -> bool:
		if not self.is_personal:
			self._personal_enc_title_key = None
			return False

		if not isinstance(device_cert, CTCert):
			raise DataProcessingError("Expecting CTCert for device cert if being given")

		if self._device_id != device_cert.device_id:
			raise DataProcessingError("Device certificate's device id must match the one on ticket")

		if act_first_import:
			key = self._decrypt_personal_tik_key_layer(
				self._enc_title_key,
				self._ticket_id,
				self._ec_pubkey,
				device_cert
			)
			self._personal_enc_title_key = self._enc_title_key
			self._enc_title_key = key
			self._tik_block = self._tik_block[:0x7F] + key + self._tik_block[0x8F:]
		else:
			self._personal_enc_title_key = self._encrypt_personal_tik_key_layer(
				self._enc_title_key,
				self._ticket_id,
				self._ec_pubkey,
				device_cert
			)

		return True

	def has_rights_to_index(self, index: typing.SupportsInt) -> bool:
		index = int(index)
		if index >= 65536:
			return False
		return (self._rights & (1 << index)) != 0
