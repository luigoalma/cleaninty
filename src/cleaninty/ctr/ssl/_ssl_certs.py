import pathlib, typing

from ..environment import find_in_config_dirs
from .. import keys

_certs_dir = pathlib.Path(__file__).resolve().parent / '_certificates'

_cert_files_by_id = {
	0x1: 'Nintendo CA.pem',
	0x2: 'Nintendo CA - G2.pem',
	0x3: 'Nintendo CA - G3.pem',
	0x4: 'Nintendo Class 2 CA.pem',
	0x5: 'Nintendo Class 2 CA - G2.pem',
	0x6: 'Nintendo Class 2 CA - G3.pem',
	0x7: 'GTE CyberTrust Global Root.pem',
	0x8: 'AddTrust External CA Root.pem',
	0x9: 'COMODO RSA Certification Authority.pem',
	0xA: 'USERTrust RSA Certification Authority.pem',
	0xB: 'DigiCert High Assurance EV Root CA.pem'
}

def _ca_id_path(_id: int) -> typing.Optional[str]:
	if _id < 0:
		pem = '3ds-ssl-ca-bundle.crt'
	else:
		pem = _cert_files_by_id.get(_id, None)

	if pem is None:
		return None

	path = _certs_dir / pem

	if path.is_file():
		return str(path)

	paths = find_in_config_dirs('SSLCertificates/' + pem)

	return paths[0] if paths else None

def _client_cert_path_tuple(is_dev: bool = False) -> typing.Tuple[typing.Optional[str], typing.Optional[str]]:
	cert = 'ctr-common-1-cert-dev.pem' if is_dev else 'ctr-common-1-cert-prod.pem'
	key = 'ctr-common-1-key-dev.pem' if is_dev else 'ctr-common-1-key-prod.pem'

	certpath = _certs_dir / cert
	keypath = _certs_dir / key

	if not certpath.is_file():
		certpaths = find_in_config_dirs('SSLCertificates/client/' + cert)
		certpath = certpaths[0] if certpaths else None

	if not keypath.is_file():
		keypaths = find_in_config_dirs('SSLCertificates/client/' + key)
		keypath = keypaths[0] if keypaths else None

	return (str(certpath), str(keypath))
