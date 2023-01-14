from struct import unpack
import typing, hashlib, os, pathlib, json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.primitives.ciphers as crypto_ciphers

from .environment import find_in_config_dirs
from . import constants

__all__ = [
	"get_b9_x",
	"get_b9_y",
	"get_b9_n",
	"get_rsa_key",
	"scramble_keys",
	"unscramble_key_with_x",
	"unscramble_key_with_y",
	"register_additional_b9_paths"
]

_b9_keydata = {
	'retail': {
		'x': (None,)*64, 'y': (None,)*64, 'n': (None,)*64,
		'otp': {'key': None, 'iv': None},
		'keyblob': None,
		'rsa': (None,)*11,
		'rsa_priv': [None,]*8
	},
	'dev': {
		'x': (None,)*64, 'y': (None,)*64, 'n': (None,)*64,
		'otp': {'key': None, 'iv': None},
		'keyblob': None,
		'rsa': (None,)*11,
		'rsa_priv': [None,]*8
	}
}

_b9_prot_sha512_hash = 'd1f10601193b4154d8c7667102f7c5e270fea49d50b04c6f7e374dbf15937c1a5568236bb551a5cb73bf789c9454c2727118c5eb849f0728561273b684ca1ae7'

_loaded_b9 = False

_additional_b9_paths: typing.List[str] = []

def _get_b9_env() -> typing.List[str]:
	env = os.environ.get('BOOT9_PATH', None)
	if not env:
		return []

	try:
		path = pathlib.Path(env).resolve()
		env = str(path) if path.is_file() else []

	except Exception:
		env = []

	return env

def _load_b9_keys() -> bool:
	global _loaded_b9
	if _loaded_b9:
		return True

	paths = find_in_config_dirs('boot9.bin')
	paths += find_in_config_dirs('boot9_protected.bin')
	paths += _get_b9_env() 
	paths += _additional_b9_paths
	paths = list(set(paths))

	got_b9 = False

	for i in paths:
		try:
			with open(i, 'rb') as file:
				data = file.read(0x10000)

			if len(data) == 0x10000:
				data = data[0x8000:]
			else:
				data = data[:0x8000]
			
			if len(data) < 0x8000:
				continue

			if hashlib.sha512(data).hexdigest() != _b9_prot_sha512_hash:
				continue

			got_b9 = True
			break
			
		except Exception:
			continue

	if not got_b9:
		return False

	be = lambda x: int.from_bytes(x, 'big')

	e = 0x10001

	rsa_raw_retail, rsa_raw_dev, \
	otp_key_retail, otp_iv_retail, otp_key_dev, otp_iv_dev, \
	keyblob_raw_retail, keyblob_raw_dev = unpack('12512x 4864s 4864s 16s 16s 16s 16s 320x 1024s 1024s 8096x', data)

	keydata = {
		'retail': {
			'x': None, 'y': None, 'n': None,
			'otp': {'key': be(otp_key_retail), 'iv': be(otp_iv_retail)},
			'keyblob': keyblob_raw_retail,
			'rsa': None,
			'rsa_priv': [None,]*8
		},
		'dev': {
			'x': None, 'y': None, 'n': None,
			'otp': {'key': be(otp_key_dev), 'iv': be(otp_iv_dev)},
			'keyblob': keyblob_raw_dev,
			'rsa': None,
			'rsa_priv': [None,]*8
		}
	}

	rsa_keys = [[], []]

	for i, k in enumerate((unpack('256s'*19, rsa_raw_retail), unpack('256s'*19, rsa_raw_dev))):
		try:
			for j in range(0,3):
				key = rsa.RSAPublicNumbers(e, be(k[j]))
				key.public_key(default_backend()) # validate key by trying to load

				rsa_keys[i].append(key)

			for j in range(3,19,2):
				n = be(k[j])
				d = be(k[j+1])

				key = (rsa.RSAPublicNumbers(e, n), d)
				key[0].public_key(default_backend()) # validate key by trying to load

				rsa_keys[i].append(key)

		except Exception:
			return False

	keydata['retail']['rsa'] = tuple(rsa_keys[0])
	keydata['dev']['rsa'] = tuple(rsa_keys[1])
	del rsa_keys

	unpacked_keys = [
		[
			[None]*64,
			[None]*64,
			[None]*64
		],
		[
			[None]*64,
			[None]*64,
			[None]*64
		]
	]

	for i, k in enumerate((unpack('16s'*36, keyblob_raw_retail[368:-80]), unpack('16s'*36, keyblob_raw_dev[368:-80]))):
		# x
		unpacked_keys[i][0][0x2C:0x30] = [be(k[0])]*4
		unpacked_keys[i][0][0x30:0x34] = [be(k[1])]*4
		unpacked_keys[i][0][0x34:0x38] = [be(k[2])]*4
		unpacked_keys[i][0][0x38:0x3C] = [be(k[3])]*4
		unpacked_keys[i][0][0x3C:0x40] = [be(k[j]) for j in range(4,8)]

		# y
		unpacked_keys[i][1][0x04:0x0C] = [be(k[j]) for j in range(8,16)]

		# n
		unpacked_keys[i][2][0x0C:0x10] = [be(k[16])]*4
		unpacked_keys[i][2][0x10] = be(k[17])
		unpacked_keys[i][2][0x14:0x18] = [be(k[j]) for j in range(18,22)]
		unpacked_keys[i][2][0x18:0x1C] = [be(k[22])]*4
		unpacked_keys[i][2][0x1C:0x20] = [be(k[23])]*4
		unpacked_keys[i][2][0x20:0x24] = [be(k[24])]*4
		unpacked_keys[i][2][0x24] = unpacked_keys[i][2][0x28] = be(k[25])
		unpacked_keys[i][2][0x29:0x2C] = [be(k[j]) for j in range(26,29)]
		unpacked_keys[i][2][0x2C:0x30] = [be(k[29])]*4
		unpacked_keys[i][2][0x30:0x34] = [be(k[30])]*4
		unpacked_keys[i][2][0x34:0x38] = [be(k[31])]*4
		unpacked_keys[i][2][0x38] = unpacked_keys[i][2][0x3C] = be(k[32])
		unpacked_keys[i][2][0x3D:0x40] = [be(k[j]) for j in range(33,36)]

	keydata['retail']['x'] = tuple(unpacked_keys[0][0])
	keydata['retail']['y'] = tuple(unpacked_keys[0][1])
	keydata['retail']['n'] = tuple(unpacked_keys[0][2])
	keydata['dev']['x'] = tuple(unpacked_keys[1][0])
	keydata['dev']['y'] = tuple(unpacked_keys[1][1])
	keydata['dev']['n'] = tuple(unpacked_keys[1][2])
	del unpacked_keys

	global _b9_keydata
	_b9_keydata = keydata

	_loaded_b9 = True

	return True

def _ensure_b9(fail_return_value: typing.Any):
	def inner(func):
		def wrapper(*args, **kwargs):
			if _load_b9_keys():
				return func(*args, **kwargs)
			return fail_return_value
		return wrapper
	return inner

@_ensure_b9(None)
def _decrypt_otp(otp: typing.SupportsBytes, dev: bool) -> typing.Optional[bytes]:
	otp = bytes(otp)[:0x100]
	keydata = _b9_keydata['dev' if dev else 'retail']['otp']
	decryptor = crypto_ciphers.Cipher(
		crypto_ciphers.algorithms.AES(keydata['key'].to_bytes(16, 'big')),
		crypto_ciphers.modes.CBC(keydata['iv'].to_bytes(16, 'big')),
		default_backend()
	).decryptor()
	dec_otp = decryptor.update(otp) + decryptor.finalize()
	return dec_otp

@_ensure_b9(None)
def _encrypt_otp(otp: typing.SupportsBytes, dev: bool) -> typing.Optional[bytes]:
	otp = bytes(otp)[:0x100]
	keydata = _b9_keydata['dev' if dev else 'retail']['otp']
	encryptor = crypto_ciphers.Cipher(
		crypto_ciphers.algorithms.AES(keydata['key'].to_bytes(16, 'big')),
		crypto_ciphers.modes.CBC(keydata['iv'].to_bytes(16, 'big')),
		default_backend()
	).encryptor()
	enc_otp = encryptor.update(otp) + encryptor.finalize()
	return enc_otp

@_ensure_b9(None)
def _gen_console_keys(otp_blob: typing.SupportsBytes, dev: bool) -> typing.Optional[typing.Iterable[typing.Optional[int]]]:
	keyblob = _b9_keydata['dev' if dev else 'retail']['keyblob']
	be = lambda x: int.from_bytes(x, 'big')

	hashing_blob = bytes(otp_blob)[:0x1C] + keyblob[:36]
	blob_hash = hashlib.sha256(hashing_blob).digest()

	key = scramble_keys(be(blob_hash[0:16]), be(blob_hash[16:32]))
	if key is None:
		return None

	key = key.to_bytes(16, 'big')

	genblobs = (
		unpack('36x16s64s', keyblob[0:116]),
		unpack('36x16s64s', keyblob[116:232]),
		unpack('36x16s64s', keyblob[184:300]),
		unpack('36x16s64s', keyblob[300:416])
	)

	make_encryptor = lambda iv: crypto_ciphers.Cipher(
		crypto_ciphers.algorithms.AES(key),
		crypto_ciphers.modes.CBC(iv),
		default_backend()
	).encryptor()
	encrypt = lambda encryptor, data: encryptor.update(data) + encryptor.finalize()

	key_blobs = (
		encrypt(make_encryptor(genblobs[0][0]), genblobs[0][1]),
		encrypt(make_encryptor(genblobs[1][0]), genblobs[1][1]),
		encrypt(make_encryptor(genblobs[2][0]), genblobs[2][1]),
		encrypt(make_encryptor(genblobs[3][0]), genblobs[3][1])
	)

	keys = [None]*64

	keys[0x04:0x08] = [be(key_blobs[0][0:16])]*4
	keys[0x08:0x0C] = [be(key_blobs[0][16:32])]*4
	keys[0x0C:0x10] = [be(key_blobs[0][32:48])]*4
	keys[0x10] = be(key_blobs[0][48:64])
	keys[0x14:0x18] = [be(key_blobs[1][i:i+16]) for i in range(0,64,16)]
	keys[0x18:0x1C] = [be(key_blobs[2][0:16])]*4
	keys[0x1C:0x20] = [be(key_blobs[2][16:32])]*4
	keys[0x20:0x24] = [be(key_blobs[2][32:48])]*4
	keys[0x24] = be(key_blobs[2][48:64])
	keys[0x28:0x2C] = [be(key_blobs[3][i:i+16]) for i in range(0,64,16)]

	return tuple(keys)

@_ensure_b9(None)
def get_b9_x(slot: int, dev: bool) -> typing.Optional[int]:
	if not 0 <= slot < 64:
		return None
	return _b9_keydata['dev' if dev else 'retail']['x'][slot]

@_ensure_b9(None)
def get_b9_y(slot: int, dev: bool) -> typing.Optional[int]:
	if not 0 <= slot < 64:
		return None
	return _b9_keydata['dev' if dev else 'retail']['y'][slot]

@_ensure_b9(None)
def get_b9_n(slot: int, dev: bool) -> typing.Optional[int]:
	if not 0 <= slot < 64:
		return None
	return _b9_keydata['dev' if dev else 'retail']['n'][slot]

@_ensure_b9(None)
def get_rsa_key(index: int, dev: bool) -> typing.Union[
	rsa.RSAPublicKey, rsa.RSAPublicKeyWithSerialization,
	rsa.RSAPrivateKey, rsa.RSAPrivateKeyWithSerialization,
	None
]:
	global _b9_keydata

	if not 0 <= index < 11:
		return None

	sel = 'dev' if dev else 'retail'

	r = _b9_keydata[sel]['rsa'][index]

	if index < 3:
		return rsa.RSAPublicNumbers(
			r.e, r.n
		).public_key(default_backend())

	pub = r[0]
	p_index = index-3
	priv = _b9_keydata[sel]['rsa_priv'][p_index]

	if priv is None:
		n, e, d = (pub.n, pub.e, r[1])

		p, q = rsa.rsa_recover_prime_factors(n, e, d)
		p, q = (p, q) if p > q else (q, p)
		dmp1 = rsa.rsa_crt_dmp1(d, p)
		dmq1 = rsa.rsa_crt_dmq1(d, q)
		iqmp = rsa.rsa_crt_iqmp(p, q)
		key = rsa.RSAPrivateNumbers(
			p, q, d, dmp1, dmq1, iqmp,
			rsa.RSAPublicNumbers(e, n)
		)
		ret = key.private_key(default_backend())

		_b9_keydata[sel]['rsa_priv'][p_index] = key

		return ret
	else:
		r = priv
		pub = r.public_numbers

	return rsa.RSAPrivateNumbers(
		r.p, r.q, r.d, r.dmp1, r.dmq1, r.iqmp,
		rsa.RSAPublicNumbers(pub.e, pub.n)
	).private_key(default_backend())

constants._load_const_c()

def scramble_keys(x: int, y: int) -> typing.Optional[int]:
	if constants._aes_const_c is None:
		constants._load_const_c()
		if constants._aes_const_c is None:
			return None

	mask = (1<<128)-1
	x &= mask
	y &= mask
	tmp = (x << 2) | (x >> 126)
	tmp ^= y
	tmp += constants._aes_const_c
	tmp &= mask
	tmp = (tmp << 87) | (tmp >> 41)
	return tmp & mask

def unscramble_key_with_x(n: int, x: int) -> typing.Optional[int]:
	if constants._aes_const_c is None:
		constants._load_const_c()
		if constants._aes_const_c is None:
			return None

	mask = (1<<128)-1
	n &= mask
	x &= mask
	tmp = (n << 41) | (n >> 87)
	tmp -= constants._aes_const_c
	tmp &= mask
	tmp ^= (x << 2) | (x >> 126)
	return tmp & mask

def unscramble_key_with_y(n: int, y: int) -> typing.Optional[int]:
	if constants._aes_const_c is None:
		constants._load_const_c()
		if constants._aes_const_c is None:
			return None

	mask = (1<<128)-1
	n &= mask
	y &= mask
	tmp = (n << 41) | (n >> 87)
	tmp -= constants._aes_const_c
	tmp &= mask
	tmp ^= y
	tmp = (tmp << 126) | (tmp >> 2)
	return tmp & mask

def register_additional_b9_paths(*args):
	global _additional_b9_paths

	paths = []

	for i in args:
		try:
			path = pathlib.Path(i).resolve()
			if not path.is_file():
				continue

			paths.append(str(path))

		except Exception:
			pass

	_additional_b9_paths = list(set(_additional_b9_paths + paths))
