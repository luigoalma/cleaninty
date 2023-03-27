import urllib.parse, json, typing, io

from .soap.manager import CtrSoapManager
from . import exception
from .ssl import _ssl_certs
from ..connection import Connection, SimpleDownloadBuffer
from ._py_ver_fixes import CTRModel_T

class InvalidManagerStateException(exception.CTRExceptionBase):
	"""General Invalid State of the Soap Manager error"""

class InvalidCookieException(exception.CTRExceptionBase):
	"""General Cookie error"""

class NinjaException(exception.CTRExceptionBase):
	"""General Ninja response error"""
	def __init__(self, *args, **kwds):
		errorcode = kwds.pop('errorcode', -1)
		errormessage = kwds.pop('errormessage', None)
		data = kwds.pop('data', None)

		super().__init__(*args, **kwds)

		self._errorcode = errorcode
		self._errormessage = errormessage
		self._data = data

	@property
	def errorcode(self) -> typing.Optional[int]:
		return self._errorcode

	@property
	def errormessage(self) -> typing.Optional[str]:
		return self._errormessage

	@property
	def responsedata(self) -> typing.Optional[bytes]:
		return self._data

# Very very bare object, early object dev
class NinjaManager:
	def __init__(
		self,
		soap_manager: CtrSoapManager,
		shop: bool,
		tiger_version: typing.Optional[typing.Tuple[int, int]] = None,
		friend_code: typing.Optional[int] = None,
		macaddr: typing.Optional[int] = None
	):
		if not isinstance(soap_manager, CtrSoapManager):
			raise exception.ClassInitError("Excepted a CTR SOAP Manager")
		self.soap_manager = soap_manager

		if not shop:
			self.user_agent  = 'CARDBOARD-6.0'
		else:
			self.user_agent  = f'TIGER-{tiger_version[0]}.{tiger_version[1]}/'
			self.user_agent += f'{self._model_select()}-{self.soap_manager.region}-{self.soap_manager.language}_{self.soap_manager.country}/'
			self.user_agent += f'{self.soap_manager._device._otp.lfcs_id:016X}-{friend_code:016X}-{macaddr:012X}'

		self.is_cardboard = not shop
		self.friend_code = friend_code
		self.macaddr = macaddr
		self.jsessionid = None
		self.awselb = None
		self.conn = Connection()

	# lazy copy-paste from act.py, generalize it later
	def _model_select(self) -> CTRModel_T:
		model = self.soap_manager._device.model_override
		if model is not None:
			return model

		model_names = {
			0: 'CTR',
			1: 'SPR',
			2: 'FTR',
			3: 'KTR',
			4: 'RED',
			5: 'JAN'
		}
		retail_sn_firstletters = ['C', 'S', 'A', 'Y', 'Q', 'N']
		dev_sn_firstletters = ['E', 'R', 'P', 'Y', 'Q', 'N']
		_s = dev_sn_firstletters if self.soap_manager._device.is_dev else retail_sn_firstletters
		try:
			i = _s.index(self.soap_manager.serial_no[0])
		except ValueError:
			i = 3 if self.soap_manager._device.is_n3ds else 0
		return model_names.get(i, 'CTR')

	def open_without_nna(self) -> dict:
		if self.soap_manager.need_register:
			raise InvalidManagerStateException("Soap manager reports unregistered state, please register or check register status.")
		
		if self.is_cardboard:
			params = urllib.parse.urlencode(
				{
					'device_token': self.soap_manager.st_token,
					'device_account': self.soap_manager.account_id,
					'device_id': self.soap_manager.device_id,
					'lang': self.soap_manager.language,
					'country': self.soap_manager.country,
					'serial_number': self.soap_manager.serial_no
				}
			)
		else:
			params = urllib.parse.urlencode(
				{
					'mac_address': f'{self.macaddr:012X}',
					'friend_code': f'{self.friend_code:016X}',
					'serial_number': self.soap_manager.serial_no,
					'country': self.soap_manager.country,
					'lang': self.soap_manager.language,
					'shop_id': '1',
					'device_token': self.soap_manager.st_token,
					'device_account': self.soap_manager.account_id,
					'device_id': self.soap_manager.device_id
				}
			)

		buf = SimpleDownloadBuffer()
		headerbuf = SimpleDownloadBuffer()

		self.conn.reset_headers()
		self.conn.set_customrequest(None)
		self.conn.set_url('https://ninja.ctr.shop.nintendo.net/ninja/ws/my/session/!open_without_nna')
		self.conn.set_keepalive(False)
		self.conn.set_header("User-Agent", self.user_agent)
		self.conn.set_header("Accept", "application/json")
		if self.is_cardboard:
			self.conn.set_header("Accept", "application/x-www-form-urlencoded") # cardboard sets this too, because
		self.conn.set_header("Content-Type", "application/x-www-form-urlencoded")
		self.conn.set_cainfo(_ssl_certs._ca_id_path(3))
		self.conn.set_cli_cert(*self.soap_manager.ssl_cli_cert_paths)
		self.conn.set_post_data(params.encode('ascii'))
		self.conn.set_write_function(buf.write)
		self.conn.set_write_header_function(headerbuf.write)
		try:
			ret = self.conn.perform()
		except pycurl.error as e:
			raise NinjaException(
				"pycurl error"
			) from e

		if ret != 200:
			try:
				parsed = json.loads(buf.get().decode('utf-8'))
				error = parsed.get('error', None)
				errorcode = int(error.get('code', -1))
				errormessage = error.get('message', None)
			except:
				errorcode = -1
				errormessage = None
			raise NinjaException(
				"Non 200 http response",
				errorcode=errorcode,
				errormessage=errormessage,
				data=buf.get()
			)

		self.jsessionid = None
		self.awselb = None

		headerio = io.BytesIO(headerbuf.get())
		headerio.readline() # jump first line
		for line in headerio.readlines():
			line = ''.join(line.decode('utf-8').split()) # only looking for set-cookie, so no issue here
			if not line:
				break
			name, value = line.split(':', 1)
			if name.lower() != 'set-cookie':
				continue
			name, value = value.split(';',1)[0].split('=',1)
			if name == 'JSESSIONID':
				self.jsessionid = value
			if name == 'AWSELB':
				self.awselb = value

		try:
			return json.loads(buf.get().decode('utf-8'))
		except:
			raise NinjaException("Parse error.", data=buf.get())

	def prepurchase_info(self, ns_uid: int):
		if self.jsessionid is None or self.awselb is None:
			raise InvalidCookieException("Missing Cookies!")

		buf = SimpleDownloadBuffer()
		headerbuf = SimpleDownloadBuffer()

		self.conn.reset_headers()
		self.conn.set_customrequest(None)
		self.conn.set_url(f'https://ninja.ctr.shop.nintendo.net/ninja/ws/{self.soap_manager.country}/title/{ns_uid}/prepurchase_info?shop_id=1&_type=json')
		self.conn.set_keepalive(True)
		self.conn.set_header("User-Agent", self.user_agent)
		self.conn.set_header("Cookie", f"JSESSIONID={self.jsessionid};AWSELB={self.awselb}")
		self.conn.set_header("Accept", "application/json")
		self.conn.set_cainfo(_ssl_certs._ca_id_path(3))
		self.conn.set_cli_cert(*self.soap_manager.ssl_cli_cert_paths)
		self.conn.set_write_function(buf.write)
		self.conn.set_write_header_function(headerbuf.write)
		try:
			ret = self.conn.perform()
		except pycurl.error as e:
			raise NinjaException(
				"pycurl error"
			) from e

		if ret != 200:
			try:
				parsed = json.loads(buf.get().decode('utf-8'))
				error = parsed.get('error', None)
				errorcode = int(error.get('code', -1))
				errormessage = error.get('message', None)
			except:
				errorcode = -1
				errormessage = None
			raise NinjaException(
				"Non 200 http response",
				errorcode=errorcode,
				errormessage=errormessage,
				data=buf.get()
			)

		try:
			return json.loads(buf.get().decode('utf-8'))
		except:
			raise NinjaException("Parse error.", data=buf.get())

	def purchase_title(self, ns_uid: int, price_id: int):
		if self.jsessionid is None or self.awselb is None:
			raise InvalidCookieException("Missing Cookies!")

		params = urllib.parse.urlencode(
			{
				'price_id': f'{price_id}'
			}
		)

		buf = SimpleDownloadBuffer()
		headerbuf = SimpleDownloadBuffer()

		self.conn.reset_headers()
		self.conn.set_customrequest(None)
		self.conn.set_url(f'https://ninja.ctr.shop.nintendo.net/ninja/ws/{self.soap_manager.country}/title/{ns_uid}/!purchase?shop_id=1&_type=json')
		self.conn.set_keepalive(False)
		self.conn.set_header("User-Agent", self.user_agent)
		self.conn.set_header("Cookie", f"JSESSIONID={self.jsessionid};AWSELB={self.awselb}")
		self.conn.set_header("Accept", "application/json")
		self.conn.set_cainfo(_ssl_certs._ca_id_path(3))
		self.conn.set_cli_cert(*self.soap_manager.ssl_cli_cert_paths)
		self.conn.set_post_data(params.encode('ascii'))
		self.conn.set_write_function(buf.write)
		self.conn.set_write_header_function(headerbuf.write)
		try:
			ret = self.conn.perform()
		except pycurl.error as e:
			raise NinjaException(
				"pycurl error"
			) from e

		if ret != 200:
			try:
				parsed = json.loads(buf.get().decode('utf-8'))
				error = parsed.get('error', None)
				errorcode = int(error.get('code', -1))
				errormessage = error.get('message', None)
			except:
				errorcode = -1
				errormessage = None
			raise NinjaException(
				"Non 200 http response",
				errorcode=errorcode,
				errormessage=errormessage,
				data=buf.get()
			)

		try:
			return json.loads(buf.get().decode('utf-8'))
		except:
			raise NinjaException("Parse error.", data=buf.get())

	def purchase_demo(self, ns_uid: int):
		if self.jsessionid is None or self.awselb is None:
			raise InvalidCookieException("Missing Cookies!")

		buf = SimpleDownloadBuffer()
		headerbuf = SimpleDownloadBuffer()

		self.conn.reset_headers()
		self.conn.set_url(f'https://ninja.ctr.shop.nintendo.net/ninja/ws/{self.soap_manager.country}/demo/{ns_uid}/!purchase?shop_id=1&_type=json')
		self.conn.set_keepalive(False)
		self.conn.set_header("User-Agent", self.user_agent)
		self.conn.set_header("Cookie", f"JSESSIONID={self.jsessionid};AWSELB={self.awselb}")
		self.conn.set_header("Accept", "application/json")
		self.conn.set_cainfo(_ssl_certs._ca_id_path(3))
		self.conn.set_cli_cert(*self.soap_manager.ssl_cli_cert_paths)
		self.conn.set_write_function(buf.write)
		self.conn.set_write_header_function(headerbuf.write)
		self.conn.set_customrequest('POST')
		try:
			ret = self.conn.perform()
		except pycurl.error as e:
			raise NinjaException(
				"pycurl error"
			) from e

		if ret != 200:
			try:
				parsed = json.loads(buf.get().decode('utf-8'))
				error = parsed.get('error', None)
				errorcode = int(error.get('code', -1))
				errormessage = error.get('message', None)
			except:
				errorcode = -1
				errormessage = None
			raise NinjaException(
				"Non 200 http response",
				errorcode=errorcode,
				errormessage=errormessage,
				data=buf.get()
			)

		try:
			return json.loads(buf.get().decode('utf-8'))
		except:
			raise NinjaException("Parse error.", data=buf.get())
