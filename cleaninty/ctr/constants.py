from struct import unpack
import typing, hashlib, json, re, threading, os

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import cryptography.hazmat.primitives.ciphers as crypto_ciphers

from .environment import find_in_config_dirs

# in the future, I want this to load any possible constant from the system's extracted data
# mainly for sake of building a ctr_constant.json that can be used by any application that wishes for system data

# ACT

_constants_json_lock = threading.RLock()

_act_cli_data = {
	'CLIENT_ID': None,
	'CLIENT_SECRET': None
}

_act_cli_hashes = {
	'25c20a9cbd5612a7f31ea45d27c18fe27bce121353daf90aaf0407cf08356769': 'CLIENT_ID',
	'c8c4ad2420d2ba824eedda113de77a8b662406b972952b64889d76cf71088c01': 'CLIENT_SECRET'
}

def _load_act_secrets(codebin: typing.Optional[bytes] = None) -> None:
	global _act_cli_data

	strs = []

	paths = find_in_config_dirs('ctr_constants.json')

	for i in paths:
		try:
			with open(i, 'r', encoding='utf-8') as j, _constants_json_lock:
				data = json.load(j)
			act = data.get('ACT', {})
			for j in ['CLIENT_ID', 'CLIENT_SECRET']:
				n = act.get(j, None)
				if n is not None and len(n) == 32:
					strs.append(n.encode('ascii'))
		except Exception:
			continue

	if codebin:
		strs += re.findall(b'[0-9a-f]{32}', codebin)

	for i in strs:
		_hash = hashlib.sha256(i).hexdigest()
		name = _act_cli_hashes.get(_hash, None)
		if name is None:
			continue
		_act_cli_data[name] = i.decode('ascii')

	if codebin:
		_save_act_secrets()

def _save_act_secrets() -> None:
	paths = find_in_config_dirs('ctr_constants.json', True)

	for i in paths:
		try:
			with open(i, 'r+', encoding='utf-8') as j, _constants_json_lock:
				try:
					data = json.load(j)
				except json.decoder.JSONDecodeError:
					data = {}
				j.seek(0)
				act = data.get('ACT', {})
				ci = _act_cli_data.get('CLIENT_ID', None)
				cs = _act_cli_data.get('CLIENT_SECRET', None)
				act['CLIENT_ID'] = ci if ci is not None else act.get('CLIENT_ID', None)
				act['CLIENT_SECRET'] = cs if cs is not None else act.get('CLIENT_SECRET', None)
				data['ACT'] = act
				out = json.dumps(data, indent=2)
				j.truncate()
				j.write(out)

		except Exception:
			continue

# CFG

_cfg_pubnums = {
	'LFCS_DEV': None,
	'LFCS_RETAIL': None,
	'SECINFO_DEV': None,
	'SECINFO_RETAIL': None
}

_cfg_key_hashes = {
	'b684323ea8b7d5966048f0c858fa066b3a5219bdef3eb84652b0951722eede4e': 'LFCS_DEV',
	'6dbf136edb9fe5b68e5681ad84ce20634db3cbacf53a025d62ad274dbac5fcfe': 'LFCS_RETAIL',
	'372889b6bee8c7e83cc4b7f5df245ccd04ff0a36fce8cebf1a85a26192b20022': 'SECINFO_DEV',
	'e109d0cce7298a46255bea27240f1630ac6cdaccb1b47a90d613171ac2ddfdda': 'SECINFO_RETAIL'
}

def _load_cfg_rsa_keys(codebin: typing.Optional[bytes] = None) -> None:
	global _cfg_pubnums

	off = -1
	keys = []

	e = 0x10001

	while codebin:
		_off = codebin[off+1:].find(b'\x30\x82\x01\x22')
		if _off == -1:
			break
		off = off + 1 + _off
		try:
			key = serialization.load_der_public_key(codebin[off:])
			if isinstance(key, rsa.RSAPublicKey) or isinstance(key, rsa.RSAPublicKeyWithSerialization):
				keys.append(key.public_numbers())
		except Exception:
			pass

	paths = find_in_config_dirs('ctr_constants.json')

	for i in paths:
		try:
			with open(i, 'r', encoding='utf-8') as j, _constants_json_lock:
				data = json.load(j)
			cfg = data.get('CFG', {})
			for j in ['LFCS_DEV_N', 'LFCS_RETAIL_N', 'SECINFO_DEV_N', 'SECINFO_RETAIL_N']:
				n = cfg.get(j, None)
				try:
					n = int(n)
				except Exception:
					continue
				keys.append(rsa.RSAPublicNumbers(e, n))
		except Exception:
			continue

	for i in keys:
		_hash = hashlib.sha256(hex(i.n).encode('ascii')).hexdigest()
		name = _cfg_key_hashes.get(_hash, None)
		if name is None:
			continue
		_cfg_pubnums[name] = rsa.RSAPublicNumbers(e, i.n)

	if codebin: # save only if potential new keys
		_save_cfg_rsa_keys()

def _save_cfg_rsa_keys() -> None:
	paths = find_in_config_dirs('ctr_constants.json', True)

	for i in paths:
		try:
			with open(i, 'r+', encoding='utf-8') as j, _constants_json_lock:
				try:
					data = json.load(j)
				except json.decoder.JSONDecodeError:
					data = {}
				j.seek(0)
				cfg = data.get('CFG', {})
				ld = _cfg_pubnums.get('LFCS_DEV', None)
				lr = _cfg_pubnums.get('LFCS_RETAIL', None)
				sd = _cfg_pubnums.get('SECINFO_DEV', None)
				sr = _cfg_pubnums.get('SECINFO_RETAIL', None)
				cfg['LFCS_DEV_N'] = f"{ld.n}" if ld is not None else cfg.get('LFCS_DEV_N', None)
				cfg['LFCS_RETAIL_N'] = f"{lr.n}" if lr is not None else cfg.get('LFCS_RETAIL_N', None)
				cfg['SECINFO_DEV_N'] = f"{sd.n}" if sd is not None else cfg.get('SECINFO_DEV_N', None)
				cfg['SECINFO_RETAIL_N'] = f"{sr.n}" if sr is not None else cfg.get('SECINFO_RETAIL_N', None)
				data['CFG'] = cfg
				out = json.dumps(data, indent=2)
				j.truncate()
				j.write(out)

		except Exception:
			continue

# P9

_p9_pubnums = {
	'CDN_TIK_WRAP': None,
	'ROOT_CERT_DEV': None,
	'ROOT_CERT_RETAIL': None,
	'CTR2_DEV': None,
	'CTR2_PROD': None
}

_p9_keys = {
	'IVS_CMAC_KEYY': None,
	'IVS_KEYY': None
}

_p9_key_hashes = {
	'a871c8f16cfc55508d57bfa5741dd8d44d5bc46c9a5361ea12b11007447ea1ae': 'CDN_TIK_WRAP',
	'6dbf136edb9fe5b68e5681ad84ce20634db3cbacf53a025d62ad274dbac5fcfe': 'LFCS_RETAIL',
	'25de2e150fa2f50c5b5e1ba3ce59e3759bbc97a401d9f22cd7a0189b52ffb9a7': 'ROOT_CERT_DEV',
	'73f65a898c67bd8e166899536cfc8f479792ecb9a279c2b8ecd214032511080a': 'ROOT_CERT_RETAIL',
	'39d33bd0c05949d1c3f98a088ac518dac73496411b5a054ff1698b682469adbd': 'CTR2_DEV_X',
	'1fdbeb696cc779f1a04f4ae99fb335ed3e36dadd8e4163d6ae8fbca94205b9cd': 'CTR2_DEV_Y',
	'77752904569351b4d895679b1dd24dd3150a7b1bed2be063ef9e5ff578d3c862': 'CTR2_PROD_X',
	'690dcb701cc12a7e0e67ad57714a608c4eb3b893bf2a648defded0c3a2f702fd': 'CTR2_PROD_Y',
	'c318d16d02c3bd7d21b9239aa7632eab412ffc08353c293f4d28345843052b3c': 'IVS_CMAC_KEYY',
	'fc8e6cc6afc33983a9d377a93031e3d1d2e37810392667c671b76ebc2abe2573': 'IVS_KEYY'
}

def _load_p9_keys(codebin: typing.Optional[bytes] = None) -> None:
	global _p9_pubnums
	global _p9_keys

	off = -1
	keys = []
	certs = []
	aes_keys = []

	e = 0x10001

	while codebin:
		_off = codebin[off+1:].find(b'\x30\x82\x01\x22')
		if _off == -1:
			break
		off = off + 1 + _off
		try:
			key = serialization.load_der_public_key(codebin[off:])
			if isinstance(key, rsa.RSAPublicKey) or isinstance(key, rsa.RSAPublicKeyWithSerialization):
				keys.append(key.public_numbers())
		except Exception:
			pass

	off = -1

	while codebin:
		_off = codebin[off+1:].find(b'\x30\x82\x03')
		if _off == -1:
			break
		off = off + 1 + _off
		try:
			size = unpack(">2xH", codebin[off:off+4])[0] + 4
			cert = x509.load_der_x509_certificate(codebin[off:off+size])
			if not isinstance(cert, x509.Certificate):
				continue
			certs.append(cert)
			# uncertain if different versions demonstrate diff alignments for keys right after one of these certs
			size_a4  = (size + 3) & 0xFFFC
			size_a8  = (size + 7) & 0xFFF8
			size_a16 = (size + 15) & 0xFFF0
			size_a32 = (size + 31) & 0xFFE0
			size_a64 = (size + 63) & 0xFFC0
			sizes = list(set([size_a4, size_a8, size_a16, size_a32, size_a64]))
			for i in sizes:
				aes_keys += [int.from_bytes(j, 'big') for j in unpack("16s16s", codebin[off+i:off+i+32])]
		except Exception:
			pass

	off = -1

	while codebin:
		_off = codebin[off+1:].find(b'\x01\x00\x01\x00\x01\x00\x01\x00')
		if _off == -1:
			break
		off = off + 1 + _off
		try:
			k1 = int.from_bytes(codebin[off+8:off+8+512], 'big')
			k2 = int.from_bytes(codebin[off+8+512:off+8+1024], 'big')
			keys.append(rsa.RSAPublicNumbers(e, k1))
			keys.append(rsa.RSAPublicNumbers(e, k2))
		except Exception:
			pass

	cert_keys = {}

	paths = find_in_config_dirs('ctr_constants.json')

	for i in paths:
		try:
			with open(i, 'r', encoding='utf-8') as j, _constants_json_lock:
				data = json.load(j)
			p9 = data.get('P9', {})
			p9_asym = p9.get('Asymmetric', {})
			p9_aes = p9.get('AES', {})

			for j in ['CDN_TIK_WRAP_N', 'ROOT_CERT_DEV_N', 'ROOT_CERT_RETAIL_N']:
				n = p9_asym.get(j, None)
				try:
					n = int(n)
				except Exception:
					continue
				keys.append(rsa.RSAPublicNumbers(e, n))

			for j in ['CTR2_DEV', 'CTR2_PROD']:
				n = p9_asym.get(j, None)
				try:
					x = int(n['X'])
					y = int(n['Y'])
				except Exception:
					continue
				cert_keys[j] = ec.EllipticCurvePublicNumbers(x, y, ec.SECT233R1())

			for j in ['IVS_CMAC_KEYY', 'IVS_KEYY']:
				k = p9_aes.get(j, None)
				try:
					k = int(k)
				except Exception:
					continue
				aes_keys.append(k)

		except Exception:
			continue

	for i in keys:
		_hash = hashlib.sha256(hex(i.n).encode('ascii')).hexdigest()
		name = _p9_key_hashes.get(_hash, None)
		if name is None or name not in ['CDN_TIK_WRAP', 'LFCS_RETAIL', 'ROOT_CERT_DEV', 'ROOT_CERT_RETAIL']:
			continue

		if name == 'LFCS_RETAIL':
			_cfg_pubnums[name] = rsa.RSAPublicNumbers(e, i.n)
		else:
			_p9_pubnums[name] = rsa.RSAPublicNumbers(e, i.n)

	for i in certs:
		cn = [j.rfc4514_string() for j in i.subject.rdns if j.rfc4514_string().startswith('CN=')]
		if len(cn) != 1:
			continue
		cn = cn[0][3:]

		names = ['NintendoCTR2dev', 'NintendoCTR2prod']
		index = names.index(cn) if cn in names else None
		if index is None:
			continue

		pubnums = i.public_key().public_numbers()
		if not isinstance(pubnums.curve, ec.SECT233R1):
			continue

		hashx = hashlib.sha256(hex(pubnums.x).encode('ascii')).hexdigest()
		hashy = hashlib.sha256(hex(pubnums.y).encode('ascii')).hexdigest()

		namex = _p9_key_hashes.get(hashx, '')
		namey = _p9_key_hashes.get(hashy, '')

		if namex != ['CTR2_DEV_X', 'CTR2_PROD_X'][index] or namey != ['CTR2_DEV_Y', 'CTR2_PROD_Y'][index]:
			continue

		name = ['CTR2_DEV', 'CTR2_PROD'][index]

		_p9_pubnums[name] = ec.EllipticCurvePublicNumbers(pubnums.x, pubnums.y, ec.SECT233R1())

	for i, j in cert_keys.items():
		hashx = hashlib.sha256(hex(j.x).encode('ascii')).hexdigest()
		hashy = hashlib.sha256(hex(j.y).encode('ascii')).hexdigest()

		namex = _p9_key_hashes.get(hashx, '')
		namey = _p9_key_hashes.get(hashy, '')

		if namex != (i + "_X") or namey != (i + "_Y"):
			continue

		_p9_pubnums[i] = ec.EllipticCurvePublicNumbers(j.x, j.y, ec.SECT233R1())

	for i in aes_keys:
		_hash = hashlib.sha256(hex(i).encode('ascii')).hexdigest()
		name = _p9_key_hashes.get(_hash, None)
		if name is None or name not in ['IVS_CMAC_KEYY', 'IVS_KEYY']:
			continue
		_p9_keys[name] = i

	if codebin: # save only if potential new keys
		_save_p9_keys()

def _save_p9_keys() -> None:
	paths = find_in_config_dirs('ctr_constants.json', True)

	for i in paths:
		try:
			with open(i, 'r+', encoding='utf-8') as j, _constants_json_lock:
				try:
					data = json.load(j)
				except json.decoder.JSONDecodeError:
					data = {}
				j.seek(0)
				p9 = data.get('P9', {})
				p9_asym = p9.get('Asymmetric', {})
				p9_aes = p9.get('AES', {})
				cw = _p9_pubnums.get('CDN_TIK_WRAP', None)
				rd = _p9_pubnums.get('ROOT_CERT_DEV', None)
				rr = _p9_pubnums.get('ROOT_CERT_RETAIL', None)
				c2d = _p9_pubnums.get('CTR2_DEV', None)
				c2p = _p9_pubnums.get('CTR2_PROD', None)
				ivscmac = _p9_keys.get('IVS_CMAC_KEYY', None)
				ivs = _p9_keys.get('IVS_KEYY', None)
				p9_asym['CDN_TIK_WRAP_N'] = f"{cw.n}" if cw is not None else p9_asym.get('CDN_TIK_WRAP_N', None)
				p9_asym['ROOT_CERT_DEV_N'] = f"{rd.n}" if rd is not None else p9_asym.get('ROOT_CERT_DEV_N', None)
				p9_asym['ROOT_CERT_RETAIL_N'] = f"{rr.n}" if rr is not None else p9_asym.get('ROOT_CERT_RETAIL_N', None)
				p9_asym['CTR2_DEV'] = {'X': f"{c2d.x}", 'Y': f"{c2d.y}"} if c2d is not None else p9_asym.get('CTR2_DEV', None)
				p9_asym['CTR2_PROD'] = {'X': f"{c2p.x}", 'Y': f"{c2p.y}"} if c2p is not None else p9_asym.get('CTR2_PROD', None)
				p9_aes['IVS_CMAC_KEYY'] = f"{ivscmac}" if ivscmac is not None else p9_asym.get('IVS_CMAC_KEYY', None)
				p9_aes['IVS_KEYY'] = f"{ivs}" if ivs is not None else p9_asym.get('IVS_KEYY', None)
				p9['Asymmetric'] = p9_asym
				p9['AES'] = p9_aes
				data['P9'] = p9
				out = json.dumps(data, indent=2)
				j.truncate()
				j.write(out)

		except Exception:
			continue

# HW AES Constant

_aes_const_c = None

def _load_const_c(constant: typing.Optional[bytes] = None) -> None:
	global _aes_const_c

	_hash_c = '6e637c42711e65cc28db9fe45d7ef3dbc6952a63b8310407befdd7cd6616286a'

	constants = []

	paths = find_in_config_dirs('ctr_constants.json')

	for i in paths:
		try:
			with open(i, 'r', encoding='utf-8') as j, _constants_json_lock:
				data = json.load(j)
			cfg = data.get('HW', {})
			n = cfg.get('AES_CONST_C', None)
			try:
				n = int(n)
			except Exception:
				continue
			constants.append(n)
		except Exception:
			continue

	for i in constants:
		if hashlib.sha256(str(i).encode('ascii')).hexdigest() != _hash_c:
			continue
		_aes_const_c = i
		return

	paths = find_in_config_dirs('aeshw_keygen_constant')

	for i in paths:
		try:
			with open(i, 'rb') as j:
				key = j.read(16)
			if len(key) != 16:
				continue
			constants.append(int.from_bytes(key, 'big'))
		except Exception:
			continue

	if constant is not None and len(constant) == 16:
		constants.append(int.from_bytes(constant, 'big'))

	for i in constants:
		if hashlib.sha256(str(i).encode('ascii')).hexdigest() != _hash_c:
			continue
		_aes_const_c = i

	if _aes_const_c is not None:
		_save_const_c()

def _save_const_c() -> None:
	paths = find_in_config_dirs('ctr_constants.json', True)

	for i in paths:
		try:
			with open(i, 'r+', encoding='utf-8') as j, _constants_json_lock:
				try:
					data = json.load(j)
				except json.decoder.JSONDecodeError:
					data = {}
				j.seek(0)
				hw = data.get('HW', {})
				hw['AES_CONST_C'] = f"{_aes_const_c}" if _aes_const_c is not None else None
				data['HW'] = hw
				out = json.dumps(data, indent=2)
				j.truncate()
				j.write(out)

		except Exception:
			continue

# SSL

def _configure_certs(codebin: bytes) -> None:
	off = -1
	certs = []

	while True:
		_off = codebin[off+1:].find(b'\x30\x82')
		if _off == -1:
			break
		off = off + 1 + _off
		try:
			size = unpack(">2xH", codebin[off:off+4])[0]
			cert = x509.load_der_x509_certificate(codebin[off:off+size+4])
			if isinstance(cert, x509.Certificate):
				certs.append(cert)
		except Exception:
			pass

	bundle_paths = find_in_config_dirs('SSLCertificates/3ds-ssl-ca-bundle.crt', True)
	bundle_crts = []

	for i in bundle_paths:
		try:
			bundle_crts.append([open(i, 'wb'), i])
		except Exception:
			pass

	for i in certs:
		cn = [j.rfc4514_string() for j in i.subject.rdns if j.rfc4514_string().startswith('CN=')]
		if len(cn) != 1:
			continue
		cn = cn[0]
		name = '_'.join('_'.join(cn[3:].split('/')).split('\\'))
		paths = find_in_config_dirs('SSLCertificates/' + name + '.pem', True)

		data = b"# " + cn[3:].encode('utf-8') + b'\n' + i.public_bytes(serialization.Encoding.PEM) + b'\n'
		for j in paths:
			try:
				with open(j, 'wb') as o:
					o.write(data)
			except Exception:
				try:
					os.unlink(j)
				except Exception:
					pass
				pass

		for j in bundle_crts:
			try:
				j[0].write(data)
			except Exception:
				try:
					j[0].close()
					os.unlink(j[1])
				except Exception:
					pass
				pass

def _configure_cli_cert_and_key(enc_cert: bytes, enc_key: bytes):
	from . import keys # keys imports constants, so I can't import keys on top

	key_retail = keys.get_b9_n(0xD, False)
	key_dev = keys.get_b9_n(0xD, True)

	cert = None
	key = None

	for i in [key_retail, key_dev]:
		try:
			if i is None:
				continue

			aes_key = i.to_bytes(16, 'big')

			decryptor = crypto_ciphers.Cipher(
				crypto_ciphers.algorithms.AES(aes_key),
				crypto_ciphers.modes.CBC(enc_cert[:16]),
				default_backend()
			).decryptor()
			_cert = decryptor.update(enc_cert[16:]) + decryptor.finalize()

			if _cert[:2] != b'\x30\x82':
				continue

			size = unpack(">2xH", _cert[:4])[0]
			cert = x509.load_der_x509_certificate(_cert[:size+4])

			decryptor = crypto_ciphers.Cipher(
				crypto_ciphers.algorithms.AES(aes_key),
				crypto_ciphers.modes.CBC(enc_key[:16]),
				default_backend()
			).decryptor()
			_key = decryptor.update(enc_key[16:]) + decryptor.finalize()

			key = serialization.load_der_private_key(_key, password=None)

			k1 = cert.public_key()
			k2 = key.public_key()

			if type(k1) is type(k2) and k1.public_numbers() == k2.public_numbers():
				break

			cert = None
			key = None
		except Exception:
			pass

	if cert is None or key is None:
		return

	cn = [i.rfc4514_string() for i in cert.subject.rdns if i.rfc4514_string().startswith('CN=')]
	if len(cn) != 1:
		return
	cn = cn[0][3:]

	names = ['CTR Common Prod 1', 'CTR Common Dev 1']
	i = names.index(cn) if cn in names else None

	if i is None:
		return

	names = (
		('ctr-common-1-cert-prod.pem', 'ctr-common-1-key-prod.pem'),
		('ctr-common-1-cert-dev.pem', 'ctr-common-1-key-dev.pem')
	)[i]

	for i in find_in_config_dirs('SSLCertificates/client/' + names[0], True):
		try:
			with open(i, 'wb') as o:
				o.write(cert.public_bytes(serialization.Encoding.PEM))
		except Exception:
			try:
				os.unlink(i)
			except Exception:
				pass
			pass

	for i in find_in_config_dirs('SSLCertificates/client/' + names[1], True):
		try:
			with open(i, 'wb') as o:
				o.write(key.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption()
				))
		except Exception:
			try:
				os.unlink(i)
			except Exception:
				pass
			pass
