import urllib.parse, json, typing

from .soap.manager import CtrSoapManager
from . import exception
from .ssl import _ssl_certs
from ..connection import Connection, SimpleDownloadBuffer

class InvalidManagerStateException(exception.CTRExceptionBase):
	"""General Invalid State of the Soap Manager error"""

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
	def __init__(self, soap_manager: CtrSoapManager):
		if not isinstance(soap_manager, CtrSoapManager):
			raise exception.ClassInitError("Excepted a CTR SOAP Manager")
		self.soap_manager = soap_manager
		self.user_agent = 'CARDBOARD-6.0' # there's information i still need to collect to do a TIGER request
		self.is_cardboard = True

	def open_without_nna(self) -> dict:
		if self.soap_manager.need_register:
			return InvalidManagerStateException("Soap manager reports unregistered state, please register or check register status.")
		# if Cardboard, TIGER has more paramaters
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

		buf = SimpleDownloadBuffer()

		conn = Connection()
		conn.set_url('https://ninja.ctr.shop.nintendo.net/ninja/ws/my/session/!open_without_nna')
		conn.set_keepalive(False)
		conn.set_header("User-Agent", self.user_agent)
		conn.set_header("Accept", "application/json")
		conn.set_header("Accept", "application/x-www-form-urlencoded") # cardboard sets this too, because
		conn.set_header("Content-Type", "application/x-www-form-urlencoded")
		conn.set_cainfo(_ssl_certs._ca_id_path(3))
		conn.set_cli_cert(*self.soap_manager.ssl_cli_cert_paths)
		conn.set_post_data(params.encode('ascii'))
		conn.set_write_function(buf.write)
		ret = conn.perform()

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
