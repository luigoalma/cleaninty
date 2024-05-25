from struct import pack, unpack
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import digitalsignature as digsign
from ..exception import ClassInitError

__all__ = [
	"Certificate",
	"CertificateKeyType",
	"CertificateKeyTypeError"
]

class CertificateKeyTypeError(digsign.KeyTypeError):
	"""General CertificateKeyType exception"""

class CertificateKeyType:
	@staticmethod
	def pubkey_block_size(entry: typing.Union[digsign.KeyType, int]) -> int:
		value = int(entry)
		if value == digsign.KeyType.RSA_4096:
			return 0x200 + 4
		if value == digsign.KeyType.RSA_2048:
			return 0x100 + 4
		if value == digsign.KeyType.ECC:
			return 0x3C
		raise CertificateKeyTypeError("Invalid KeyType")

	@staticmethod
	def pubkey_padding_block_size(entry: typing.Union[digsign.KeyType, int]) -> int:
		value = int(entry)
		if value == digsign.KeyType.RSA_4096 or value == digsign.KeyType.RSA_2048:
			return 0x34
		if value == digsign.KeyType.ECC:
			return 0x3C
		raise CertificateKeyTypeError("Invalid KeyType")

class Certificate(digsign.IssuedObject, digsign.IssuingObject):
	def __init__(self, data: typing.SupportsBytes):
		data = bytes(data)[:0x500]

		self._sign = digsign.DigitalSignature(data)

		data = data[len(self._sign):]

		if len(data) < 0x100: # 0x100 is lowest certificate block size
			raise ClassInitError("Not enough data for valid certificate")

		segments = unpack(">64sI64sI", data[:0x88])

		self._issuer_str = segments[0].decode('ascii','replace').split('\x00', 1)[0]
		self._key_type = segments[1]
		self._name_str = segments[2].decode('ascii','replace').split('\x00', 1)[0]
		self._expiration_or_unknown = segments[3]

		if not len(self._issuer_str):
			raise ClassInitError("No certificate issuer")

		if self._issuer_str.find('\uFFFD') != -1:
			raise ClassInitError("Invalid certificate issuer")

		if not len(self._name_str):
			raise ClassInitError("No certificate name")

		if self._name_str.find('\uFFFD') != -1:
			raise ClassInitError("Invalid certificate name")

		block_size = CertificateKeyType.pubkey_block_size(self._key_type)
		pad_size = CertificateKeyType.pubkey_padding_block_size(self._key_type)

		self._cert_block = data[:0x88+block_size+pad_size]

		digsign.IssuingObject.__init__(
			self,
			lambda: self.key_type,
			self.public_key,
			self.private_key,
			lambda: self.full_issuer
		)

		digsign.IssuedObject.__init__(
			self,
			lambda: self._cert_block,
			lambda: self._sign,
			lambda: self.issuer,
			lambda issuer: issuer.ljust(64,'\x00').encode() + self._cert_block[0x40:],
			self._set_reissued
		)

	def __bytes__(self):
		return bytes(self._sign) + self._cert_block

	def __len__(self):
		block_size = CertificateKeyType.pubkey_block_size(self._key_type)
		pad_size = CertificateKeyType.pubkey_padding_block_size(self._key_type)

		return len(self._sign) + 0x88 + block_size + pad_size

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} sign_type={repr(self.sign_type)} issuer={self.issuer} name={self.name} key_type={repr(self.key_type)}>"

	def _set_reissued(self, sign: digsign.DigitalSignature, issuer: str, data: typing.SupportsBytes) -> None:
		self._sign = sign
		self._issuer_str = issuer
		self._cert_block = bytes(data)

	@property
	def issuer(self) -> str:
		return self._issuer_str

	@property
	def name(self) -> str:
		return self._name_str

	@property
	def full_issuer(self) -> str:
		return self._issuer_str + '-' + self._name_str

	@property
	def key_type(self) -> digsign.KeyType:
		return digsign.KeyType(self._key_type)

	@property
	def sign_type(self) -> digsign.SignatureType:
		return self._sign.sign_type

	@property
	def cert_block(self) -> bytes:
		return self._cert_block

	def public_key(
		self
	) -> typing.Union[
		ec.EllipticCurvePublicKey,
		ec.EllipticCurvePublicKeyWithSerialization,
		rsa.RSAPublicKey,
		rsa.RSAPublicKeyWithSerialization
	]:
		block_size = CertificateKeyType.pubkey_block_size(self._key_type)

		if block_size == 0x3C:
			x, y = unpack("30s30s", self._cert_block[0x88:0x88+60])
			x = int(x.hex(), 16) & ((1 << 233) - 1)
			y = int(y.hex(), 16) & ((1 << 233) - 1)
			return ec.EllipticCurvePublicNumbers(x, y, ec.SECT233R1()).public_key(default_backend())

		n, e = unpack(f">{block_size - 4}sI", self._cert_block[0x88:0x88+block_size])
		n = int.from_bytes(n, 'big')
		return rsa.RSAPublicNumbers(e, n).public_key(default_backend())

	def private_key(
		self
	) -> typing.Union[
		ec.EllipticCurvePrivateKey,
		ec.EllipticCurvePrivateKeyWithSerialization,
		rsa.RSAPrivateKey,
		rsa.RSAPrivateKeyWithSerialization,
		None
	]:
		try:
			if isinstance(self._privkey_numbers, ec.EllipticCurvePrivateNumbers):
				return ec.derive_private_key(self._privkey_numbers.private_value, ec.SECT233R1(), default_backend())
			elif isinstance(self._privkey_numbers, rsa.RSAPrivateNumbers):
				return self._privkey_numbers.private_key(default_backend())
		except Exception:
			return None

	def set_private_key(
		self,
		private_numbers: typing.Union[ec.EllipticCurvePrivateNumbers, rsa.RSAPrivateNumbers]
	) -> bool:
		block_size = CertificateKeyType.pubkey_block_size(self._key_type)

		try:
			pubkey_numbers = self.public_key().public_numbers()
			if isinstance(private_numbers, ec.EllipticCurvePrivateNumbers):
				# .private_key() fails?? but derive key is just fine??? idk man
				privkey_test = ec.derive_private_key(private_numbers.private_value, ec.SECT233R1(), default_backend())
			elif isinstance(private_numbers, rsa.RSAPrivateNumbers):
				privkey_test = private_numbers.private_key(default_backend())
			else:
				raise Exception("")
			pubkey_test_numbers = privkey_test.public_key().public_numbers()
		except Exception as e:
			return False

		if block_size == 0x3C:
			if pubkey_numbers.x != pubkey_test_numbers.x or pubkey_numbers.y != pubkey_test_numbers.y:
				return False
		else:
			if pubkey_numbers.n != pubkey_test_numbers.n or pubkey_numbers.e != pubkey_test_numbers.e:
				return False

		self._privkey_numbers = privkey_test.private_numbers()
		return True

	@classmethod
	def process_chain(cls, buffer: typing.SupportsBytes) -> typing.Iterable['Certificate']:
		chain = []

		while (buffer):
			cert = cls(buffer)
			chain.append(cert)
			buffer = buffer[len(cert):]

		return chain
