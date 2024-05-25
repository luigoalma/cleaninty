from struct import pack, unpack
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..common.certificate import Certificate, CertificateKeyType, CertificateKeyTypeError
from .constants import _load_p9_keys, _p9_pubnums

__all__ = [
	"Certificate",
	"CertificateKeyType",
	"GetRootCertKey",
	"CertificateKeyTypeError"
]

_load_p9_keys()

def GetRootCertKey(dev: bool) -> typing.Union[rsa.RSAPublicKey, rsa.RSAPublicKeyWithSerialization, None]:
	key = _p9_pubnums['ROOT_CERT_DEV'] if dev else _p9_pubnums['ROOT_CERT_RETAIL']
	if key is None:
		_load_p9_keys()
		key = _p9_pubnums['ROOT_CERT_DEV'] if dev else _p9_pubnums['ROOT_CERT_RETAIL']
		if key is None:
			return None

	return key.public_key(default_backend())
