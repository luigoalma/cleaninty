from struct import pack, unpack
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from . import certificate
from . import digitalsignature as digsign
from . import otp
from .exception import ClassInitError

__all__ = [
	"APCert"
]

class APCert(certificate.Certificate):
	def __init__(self, ctcert: otp.CTCert, titleid: typing.SupportsInt):
		if not isinstance(ctcert, otp.CTCert):
			raise ClassInitError("APCert excepts CTCert object")

		titleid = int(titleid)

		if titleid < 0 or (titleid & 0xFFFF400000000000) != 0x0004000000000000:
			raise ClassInitError("Invalid titleid")

		try:
			privkey = ec.generate_private_key(ec.SECT233R1(), default_backend())
			pubkeynumbers = privkey.public_key().public_numbers()
		except Exception as e:
			raise ClassInitError("EC Key generation error") from e

		try:
			data = pack(
				">I60x64x64sI64sI30s30s60x",
				digsign.SignatureType.ECC_SHA256,
				b"SigningStaging",
				digsign.KeyType.ECC,
				(f"AP{titleid:016x}").encode(),
				0,
				pubkeynumbers.x.to_bytes(30, 'big'),
				pubkeynumbers.y.to_bytes(30, 'big')
			)
		except Exception as e:
			raise ClassInitError("Packing error") from e

		super().__init__(data)

		try:
			self.reissue(ctcert)
			self.verify(ctcert)
		except Exception as e:
			raise ClassInitError("Could not sign or verify the generated APCert") from e

		if not self.set_private_key(privkey.private_numbers()):
			raise ClassInitError("APCert private key was not successfully loaded!")

		self._ap_title_id = titleid

	@property
	def ap_title_id(self) -> int:
		return self._ap_title_id
