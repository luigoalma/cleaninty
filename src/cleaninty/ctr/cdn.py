from enum import IntEnum, unique
import typing, os, base64, abc

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.primitives.ciphers as crypto_ciphers

from .ticket import Ticket
from .title import Title
from .tmd import TMD, ContentChunkRecord
from .certificate import Certificate
from .exception import CTRExceptionBase, ClassInitError, DataProcessingError
from .ssl import _ssl_certs
from ..connection import Connection, SimpleDownloadBuffer, MultiWriter, WriterFuncType
from .constants import _load_p9_keys, _p9_pubnums

__all__ = [
	"CDN",
	"CDNDownloadStage",
	"AssistedCDNDownload"
]

_load_p9_keys()

def _CDNTicketEnc(tik):
	if (((len(tik) + 15) >> 4) << 4) >= 0x2800:
		raise DataProcessingError("3DS caps tickets to be sent by 0x2800")

	tik = bytes(tik)
	tik += bytes((16 - (len(tik) & 0xF)) & 0xF)
	key_iv = os.urandom(32)

	cdnkey = _p9_pubnums['CDN_TIK_WRAP']
	if cdnkey is None:
		_load_p9_keys()
		cdnkey = _p9_pubnums['CDN_TIK_WRAP']
		if cdnkey is None:
			raise DataProcessingError("No CDN Key!! Provide up-to-date P9 code.bin to load function")

	klen = (cdnkey.n.bit_length() + 7) // 8
	plen = klen - len(key_iv) - 3
	if plen <= 0:
		raise DataProcessingError("Bad Key? Was it modified?")

	m = b'\x00\x01' + b'\xFF' * plen + b'\x00' + key_iv
	m = int.from_bytes(m, 'big')
	m = pow(m, cdnkey.e, cdnkey.n).to_bytes(klen, 'big')

	encryptor = crypto_ciphers.Cipher(
		crypto_ciphers.algorithms.AES(key_iv[:16]),
		crypto_ciphers.modes.CBC(key_iv[16:]),
		default_backend()
	).encryptor()

	tik_enc = encryptor.update(tik) + encryptor.finalize()

	return (base64.b64encode(m).decode('ascii'), base64.b64encode(tik_enc).decode('ascii'))

@unique
class CDNDownloadStage(IntEnum):
	CETK = 0
	TMD = 1
	CONTENT = 2
	END = 3

class AssistedCDNDownload(metaclass=abc.ABCMeta):
	@abc.abstractmethod
	def notify(
		self,
		stage: CDNDownloadStage,
		chunk: ContentChunkRecord,
		starting: bool,
		http_ret: typing.SupportsInt,
		cdn: 'CDN'
	) -> typing.Optional[WriterFuncType]:
		"""
		Notify the stage
		chunk record to be downloaded if any
		if starting or ending
		if ending, what http return we got
		reference to CDN object
		return writer if starting and if applicable
		"""

	@abc.abstractmethod
	def in_error(self) -> bool:
		"""
		Check if object is in error state
		"""

	@abc.abstractmethod
	def abort(self) -> None:
		"""
		Raise abort request
		"""

class CDN:
	def __init__(
		self,
		title_id: typing.SupportsInt,
		version: typing.Optional[typing.SupportsInt] = None,
		*,
		device_id: typing.Optional[typing.SupportsInt] = None,
		account_id: typing.Optional[typing.SupportsInt] = None,
		ticket: typing.Optional[Ticket] = None,
		content_prefix: typing.Optional[str] = None,
		uncached_content_prefix: typing.Optional[str] = None,
		system_content_prefix: typing.Optional[str] = None,
		system_uncached_content_prefix: typing.Optional[str] = None,
		is_dev: bool = False
	):
		self._tid = int(title_id) & 0xFFFFFFFFFFFFFFFF

		if not Title.is_ctr(self._tid):
			raise ClassInitError("Expected ctr title")

		self._version = (int(version) & 0xFFFF) if version is not None else None

		self._device_id = ((4<<32) | (int(device_id) & 0xFFFFFFFF)) if device_id else None
		self._account_id = (int(account_id) & 0xFFFFFFFF) if account_id else None

		if ticket is not None and not isinstance(ticket, Ticket):
			raise ClassInitError("ticket was given but is not a class Ticket")

		if ticket is not None and ticket.title_id != self._tid:
			raise ClassInitError("ticket's title id does not match CDN download target")

		self._tik = ticket

		self._urls = {
			'cdn': str(content_prefix) if content_prefix is not None else 'http://ccs.cdn.c.shop.nintendowifi.net/ccs/download',
			'uncached_cdn': str(uncached_content_prefix) if uncached_content_prefix is not None else 'https://ccs.c.shop.nintendowifi.net/ccs/download',
			'syscdn': str(system_content_prefix) if system_content_prefix is not None else 'http://nus.cdn.c.shop.nintendowifi.net/ccs/download',
			'uncached_syscdn': str(system_uncached_content_prefix) if system_uncached_content_prefix is not None else 'https://ccs.c.shop.nintendowifi.net/ccs/download'
		}

		self._tmd_raw = None
		self._tmd = None
		self._cetk_raw = None
		self._certs = {}

		self._is_dev = bool(is_dev)

		self._conn = self._create_connection(self._is_dev)

	@staticmethod
	def _create_connection(is_dev: bool = False) -> Connection:
		conn = Connection()
		conn.set_keepalive(True)
		conn.set_cainfo(_ssl_certs._ca_id_path(3))
		conn.set_cli_cert(*_ssl_certs._client_cert_path_tuple(is_dev))

		return conn

	def _update_certchain(self, chainblock: typing.SupportsBytes) -> None:
		certs = Certificate.process_chain(chainblock)
		for i in certs:
			self.add_additional_cert(i)

	@property
	def target_version(self):
		return self._version

	@property
	def tmd(self) -> typing.Optional[TMD]:
		return self._tmd

	@property
	def ticket(self) -> typing.Optional[Ticket]:
		return self._tik

	@property
	def tmd_raw(self) -> typing.Optional[bytes]:
		return self._tmd_raw

	@property
	def ticket_raw(self) -> typing.Optional[bytes]:
		return self._cetk_raw

	@property
	def certs(self) -> typing.Dict[str, Certificate]:
		return self._certs.copy()

	@property
	def is_sys_tid(self) -> bool:
		return Title.is_ctranysys(self._tid)

	@property
	def ignore_tik(self) -> bool:
		return Title.is_ctranysys(self._tid) or Title.is_ctrdlp(self._tid)

	@property
	def tmd_url(self) -> str:
		base_url = self._urls['uncached_syscdn' if self.is_sys_tid else 'uncached_cdn']
		url = base_url + f'/{self._tid:016X}/tmd'
		if not self._device_id and not self._account_id:
			return url
		url += '?'
		if self._device_id:
			url += f'deviceId={self._device_id}'
		if self._device_id and self._account_id:
			url += '&'
		if self._account_id:
			url += f'accountId={self._account_id}'
		return url

	@property
	def cetk_url(self) -> typing.Optional[str]:
		if not self.is_sys_tid:
			return None

		return self._urls['syscdn'] + f'/{self._tid:016X}/cetk'

	def content_url(self, c_id: typing.SupportsInt) -> str:
		base_url = self._urls['syscdn' if self.is_sys_tid else 'cdn']
		return base_url + f'/{self._tid:016X}/{(int(c_id) & 0xFFFFFFFF):08X}'

	def download_tmd(self, write: typing.Optional[WriterFuncType] = None) -> int:
		if write is not None and not callable(write):
			raise DataProcessingError("non callable writer")

		buf = SimpleDownloadBuffer()
		write_func = buf.write if write is None else MultiWriter([buf.write, write]).write

		self._conn.reset_headers()
		self._conn.set_url(self.tmd_url)
		self._conn.set_write_function(write_func)
		ret = self._conn.perform()

		if ret != 200:
			return ret

		self._tmd_raw = buf.get()
		self._tmd = TMD(self._tmd_raw)
		self._update_certchain(self._tmd_raw[len(self._tmd):])

		return ret

	def download_cetk(self, write: typing.Optional[WriterFuncType] = None) -> typing.Optional[int]:
		if write is not None and not callable(write):
			raise DataProcessingError("non callable writer")

		url = self.cetk_url
		if url is None:
			return None

		buf = SimpleDownloadBuffer()
		write_func = buf.write if write is None else MultiWriter([buf.write, write]).write

		self._conn.reset_headers()
		self._conn.set_url(url)
		self._conn.set_write_function(write_func)
		ret = self._conn.perform()

		if ret != 200:
			return ret

		self._cetk_raw = buf.get()
		self._tik = Ticket(self._cetk_raw)
		self._update_certchain(self._cetk_raw[len(self._tik):])

		return ret

	def download_content_id(self, c_id: typing.SupportsInt, write_func: typing.Optional[WriterFuncType]) -> int:
		if write_func is not None and not callable(write_func):
			raise DataProcessingError("non callable writer")

		self._conn.reset_headers()
		self._conn.set_url(self.content_url(c_id))
		if not self.ignore_tik and self._tik:
			b64_enckey, b64_enctik = _CDNTicketEnc(self._tik)
			self._conn.set_header("X-Authentication-Key", b64_enckey)
			self._conn.set_header("X-Authentication-Data", b64_enctik)
		self._conn.set_nobody(write_func is None)
		self._conn.set_write_function((lambda x: None) if write_func is None else write_func)
		ret = self._conn.perform()

		return ret

	def download(
		self,
		assistance: AssistedCDNDownload,
		right_check: bool = True,
		content_error_continue: bool = False
	) -> bool:
		if not isinstance(assistance, AssistedCDNDownload):
			raise DataProcessingError("unexpected assistance type")

		if self.is_sys_tid:
			writer = assistance.notify(CDNDownloadStage.CETK, None, True, 0, self)
			if writer is None and assistance.in_error():
				assistance.abort()
				return False

			ret = self.download_cetk(
				writer
			)
			assistance.notify(CDNDownloadStage.CETK, None, False, ret, self)
			if assistance.in_error():
				assistance.abort()
				return False

		writer = assistance.notify(CDNDownloadStage.TMD, None, True, 0, self)
		if writer is None and assistance.in_error():
			assistance.abort()
			return False

		ret = self.download_tmd(
			writer
		)
		assistance.notify(CDNDownloadStage.TMD, None, False, ret, self)
		if ret != 200 or assistance.in_error():
			assistance.abort()
			return False

		dlc = Title.is_ctrdlc(self._tid)

		for i in self._tmd.content_chunk_records:
			right = not dlc or \
				not right_check or \
				self._tik is None or \
				self._tik.has_rights_to_index(i.index)
			if not right:
				continue

			writer = assistance.notify(CDNDownloadStage.CONTENT, i, True, 0, self)
			if writer is None:
				if assistance.in_error():
					assistance.abort()
					return False
				continue

			ret = self.download_content_id(
				i.id,
				writer
			)
			assistance.notify(CDNDownloadStage.CONTENT, i, False, ret, self)
			if assistance.in_error():
				assistance.abort()
				return False

			if not content_error_continue and ret != 200:
				assistance.abort()
				return False

		assistance.notify(CDNDownloadStage.END, None, False, 0, self)
		if assistance.in_error():
			assistance.abort()
			return False

		return True

	def add_additional_cert(self, new_cert: Certificate) -> None:
		cert = self._certs.get(new_cert.full_issuer, None)
		if cert is not None and bytes(cert) != bytes(new_cert):
			raise DataProcessingError("Discrepancy found, duplicated cert mismatch previous downloaded one")

		self._certs[new_cert.full_issuer] = new_cert
