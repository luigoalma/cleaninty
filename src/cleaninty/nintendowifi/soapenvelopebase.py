from enum import IntEnum, unique
import typing, re, base64, time
import defusedxml.ElementTree as ET
from ..xml_helper import XmlParseHelper, XMLParseError, XML_Element

from .soapsessionmanager import SoapSessionManager
from ..exception import CleanintyExceptionBase, ClassInitError
from ..connection import Connection, SimpleDownloadBuffer

__all__ = [
	"SoapEnvelopeBase",
	"SoapSubNames",
	"ObjectTimingEmuHelper",
	"InvalidTagError",
	"XMLParseError",
	"SoapError",
	"ManagerTypeError"
]

class InvalidTagError(CleanintyExceptionBase):
	"""General SoapEnvelopeBase invalid tag exception"""

class SoapError(CleanintyExceptionBase):
	"""General SoapEnvelopeBase SOAP error"""

class SoapCodeError(CleanintyExceptionBase):
	"""General SoapEnvelopeBase SOAP ErrorCode error"""
	def __init__(self, *args, **kwds):
		errorcode = kwds.pop('errorcode', -1)
		errormessage = kwds.pop('errormessage', None)

		super().__init__(*args, **kwds)

		self._errorcode = errorcode
		self._errormessage = errormessage

	@property
	def soaperrorcode(self) -> int:
		return self._errorcode

	@property
	def soaperrormessage(self) -> str:
		return self._errormessage

class ManagerTypeError(CleanintyExceptionBase, TypeError):
	"""General SoapEnvelopeBase manager type error"""

_msg_start_template = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                   xmlns:{0}="urn:{0}.wsapi.broadon.com">
<SOAP-ENV:Body>
<{0}:{1} xsi:type="{0}:{1}RequestType">
<{0}:Version>{2}</{0}:Version>
<{0}:MessageId>EC-{3}-{4}</{0}:MessageId>
"""

_msg_end_template = """</{0}:{1}>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

# more intended for __init__ methods, or functions with self and manager as second arg
def ObjectTimingEmuHelper(min_time, rng_multiplier = 0):
	def inner1(func):
		def inner2(self, manager, *args, **kwds):
			if not isinstance(manager, SoapSessionManager):
				raise ManagerTypeError("Can't emulate timing without manager object")
			if not manager.is_time_emu_enabled:
				return func(self, manager, *args, **kwds)
			t = time.monotonic()
			try:
				ret = func(self, manager, *args, **kwds)
			finally:
				t = min_time - (time.monotonic() - t)
				manager.sleep_with_rng_curve(0 if t < 0 else t, rng_multiplier)
			return ret
		return inner2
	return inner1

@unique
class SoapSubNames(IntEnum):
	NUS = 0
	ECS = 1
	IAS = 2
	CAS = 3
	BGS = 4

	@classmethod
	def get_name(cls, value: typing.Union['SoapSubNames', int]) -> typing.Union[str, None]:
		try:
			return cls(int(value)).name.lower()
		except Exception:
			return None

class SoapEnvelopeBase(XmlParseHelper):
	def __init__(
		self,
		sub_name: typing.Union[SoapSubNames, int],
		soap_action_name: str,
		session_manager: SoapSessionManager,
		use_st_token: bool,
		keepalive: bool,
		version2: bool = True
	):
		try:
			sub_name = SoapSubNames(sub_name)
		except Exception as e:
			raise ClassInitError("Invalid Sub Server Name") from e

		if sub_name == SoapSubNames.BGS:
			raise ClassInitError("BGS currently unsupported")

		if not isinstance(session_manager, SoapSessionManager):
			raise ClassInitError("Need to have session manage to be a SoapSessionManager")

		use_st_token = bool(use_st_token)
		version = "2.0" if version2 else "1.0"

		self._sub_name = SoapSubNames.get_name(sub_name)
		self._soap_action_name = str(soap_action_name)
		self._session_manager = session_manager
		self._keepalive = bool(keepalive)

		self._http_headers = []
		self._http_headers.append(['User-Agent', session_manager.user_agent])
		self._http_headers.append(['Connection', 'Keep-Alive' if session_manager.keepalive else 'close'])
		self._http_headers.append(['Accept-Charset', 'UTF-8'])
		self._http_headers.append(['Content-type', 'text/xml; charset=utf-8'])
		self._http_headers.append(['SOAPAction', 'urn:{0}.wsapi.broadon.com/{1}'.format(self._sub_name, self._soap_action_name)])

		self._xml_response_namespaces = {
			'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
			'xsd': 'http://www.w3.org/2001/XMLSchema',
			'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
			'urn': 'urn:{0}.wsapi.broadon.com'.format(self._sub_name)
		}

		self._tag_stack = []

		self._response = None

		self._envelope = _msg_start_template.format(
			self._sub_name, # 0
			self._soap_action_name, # 1
			version, # 2
			session_manager.device_id, # 3
			session_manager.message_id_step, # 4
		)

		self._envelope += '<{0}:DeviceId>{1}</{0}:DeviceId>\n'.format(
			self._sub_name,
			session_manager.device_id
		)

		if sub_name != SoapSubNames.NUS:
			if session_manager.has_tokens:
				self._envelope += '<{0}:DeviceToken>{1}-{2}</{0}:DeviceToken>\n'.format(
					self._sub_name,
					"ST" if use_st_token else "WT",
					session_manager.st_token if use_st_token else session_manager.wt_token
				)
			if session_manager.account_id is not None:
				self._envelope += '<{0}:AccountId>{1}</{0}:AccountId>\n'.format(
					self._sub_name,
					session_manager.account_id
				)

		if sub_name == SoapSubNames.ECS or sub_name == SoapSubNames.CAS:
			if session_manager.application_id is not None:
				self._envelope += '<{0}:ApplicationId>{1:016x}</{0}:ApplicationId>\n'.format(
					self._sub_name,
					session_manager.application_id
				)
			if session_manager.tin is not None:
				self._envelope += '<{0}:TIN>{1}</{0}:TIN>\n'.format(
					self._sub_name,
					session_manager.tin
				)

		if session_manager.region is not None:
			self._envelope += '<{0}:{1}>{2}</{0}:{1}>\n'.format(
				self._sub_name,
				"Region" if sub_name != SoapSubNames.NUS else "RegionId",
				session_manager.region
			)

		if session_manager.country is not None:
			self._envelope += '<{0}:{1}>{2}</{0}:{1}>\n'.format(
				self._sub_name,
				"Country" if sub_name != SoapSubNames.NUS else "CountryCode",
				session_manager.country
			)

		if session_manager.virtual_device_type is not None: # seen on the Wii U for vWii
			self._envelope += '<{0}:{1}>{2}</{0}:{1}>\n'.format(
				self._sub_name,
				"VirtualDeviceType",
				session_manager.virtual_device_type
			)

		if session_manager.language is not None:
			self._envelope += '<{0}:Language>{1}</{0}:Language>\n'.format(
				self._sub_name,
				session_manager.language
			)

		if sub_name == SoapSubNames.ECS or sub_name == SoapSubNames.NUS:
			self._envelope += '<{0}:SerialNo>{1}</{0}:SerialNo>\n'.format(
				self._sub_name,
				session_manager.serial_no
			)

		# they never happen in EC 4.6 on 3ds at least
		if sub_name == SoapSubNames.ECS and session_manager.session_handle is not None and session_manager.service_ticket is not None:
			# cursed indentation
			self._envelope += '  <{0}:SessionHandle>{1}</{0}:SessionHandle>\n'.format(
				self._sub_name,
				session_manager.session_handle
			)

			self._envelope += '  <{0}:ServiceTicket>{1}</{0}:ServiceTicket>\n'.format(
				self._sub_name,
				session_manager.service_ticket
			)

			if session_manager.service_id is not None:
				self._envelope += '  <{0}:ServiceId>{1}</{0}:ServiceId>\n'.format(
					self._sub_name,
					session_manager.service_id
				)

		if sub_name == SoapSubNames.CAS and session_manager.age is not None:
			# still not sure what "Age" is in this context
			# also cursed indentation
			self._envelope += '  <{0}:Age>{1}</{0}:Age>\n'.format(
				self._sub_name,
				session_manager.age
			)

		self._closed = False

		self._timestamp = None
		self._errorcode = None
		self._errormessage = None
		self._servicestandbymode = None

	@staticmethod
	def _validate_tagname(name: str) -> bool:
		"""We'll just allow Alphabetic characters"""
		return True if re.fullmatch('^[a-zA-Z]+$', name) else False

	@staticmethod
	def _get_escaped_field(field: str) -> str:
		# there gotta be a better way to do this right?
		# but i guess i can say "it works" for now
		return re.sub('>','&gt;',re.sub('<','&lt;',re.sub("'",'&apos;',re.sub('"','&quot;',re.sub('&','&amp;',field)))))

	def _push_tag(self, name: str) -> None:
		if self._closed:
			return

		name = str(name)
		if not self._validate_tagname(name):
			raise InvalidTagError("Tag invalid for these SOAP purposes")

		self._tag_stack.append(name)

		self._envelope += '<{0}:{1}>'.format(
			self._sub_name,
			name
		)

	def _pop_tag(self) -> None:
		if self._closed:
			return

		self._envelope += '</{0}:{1}>'.format(
			self._sub_name,
			self._tag_stack.pop()
		)

	def _write_tag(self, name: str, field: str) -> None:
		if self._closed:
			return

		field = self._get_escaped_field(str(field))
		self._push_tag(name)
		self._envelope += field
		self._pop_tag()

	def _write_tag_multi_values(
		self,
		name: str,
		fields: typing.Iterable[typing.Any],
		field_transformer: typing.Callable[[typing.Any], str] = str
	) -> None:
		if self._closed:
			return

		name = str(name)
		if not self._validate_tagname(name):
			raise InvalidTagError("Tag invalid for these SOAP purposes")

		open_tag = '<{0}:{1}>'.format(
			self._sub_name,
			name
		)

		close_tag = '</{0}:{1}>'.format(
			self._sub_name,
			name
		)

		self._envelope += ''.join(
			map(
				lambda x: (open_tag + self._get_escaped_field(field_transformer(x)) + close_tag),
				fields
			)
		)

	def _close(self):
		if self._closed:
			return

		while self._tag_stack:
			self._pop_tag()

		if self._envelope[-1] != '\n':
			self._envelope += '\n'

		self._envelope += _msg_end_template.format(
			self._sub_name, # 0
			self._soap_action_name # 1
		)

		self._closed = True

		# print temporary to view
		# print(self._envelope)

	def _send(self, url: str) -> int:
		self._close()

		_cli_cert = None
		_cli_key = None
		_cli_cert_paths = self._session_manager.ssl_cli_cert_paths
		if _cli_cert_paths:
			_cli_cert = _cli_cert_paths[0]
			if len(_cli_cert_paths) > 1:
				_cli_key = _cli_cert_paths[1]

		buf = SimpleDownloadBuffer()

		conn = self._session_manager.get_connection()
		conn.reset_headers()
		conn.set_url(url)
		conn.set_keepalive(self._keepalive)
		for i in self._http_headers:
			conn.set_header(i[0], i[1])
		conn.set_cainfo(self._session_manager.ssl_cert_path)
		conn.set_cli_cert(_cli_cert, _cli_key)
		conn.set_post_data(self._envelope.encode('utf-8'))
		conn.set_write_function(buf.write)
		ret = conn.perform()

		if ret == 200:
			self._response = buf.get().decode('utf-8')
			#print(self._response)

		return ret

	@staticmethod
	def _xml_get_bool_element(
		parent: XmlParseHelper,
		element: XML_Element
	) -> bool:
		parent._xml_raise_if_any_subelement(element)
		if element.text == '0' or element.text == 'false':
			return False
		if element.text == '1' or element.text == 'true':
			return True
		raise XMLParseError("Invalid boolean field")

	def _initiate_response_parse(
		self
	) -> typing.Tuple[
		XML_Element, # root
		XML_Element # Response element
	]:
		try:
			root = ET.fromstring(self._response)
			body = self._xml_element_parse(root, 'soapenv:Body', self._xml_get_element)
			response = self._xml_element_parse(body, 'urn:{0}Response'.format(self._soap_action_name), self._xml_get_element)
			self._timestamp = self._xml_element_parse(response, 'urn:TimeStamp', self._xml_get_int_element, True)
			self._errorcode = self._xml_element_parse(response, 'urn:ErrorCode', self._xml_get_int_element)
			self._errormessage = self._xml_element_parse(response, 'urn:ErrorMessage', self._xml_get_str_element, True)
			self._servicestandbymode = self._xml_element_parse(response, 'urn:ServiceStandbyMode', self._xml_get_bool_element, self._sub_name != 'ecs')
			if self._sub_name == 'ecs':
				self._session_manager.set_service_standby(self._servicestandbymode)
			return (root, response)
		except CleanintyExceptionBase:
			raise
		except Exception as e:
			raise XMLParseError("Unexpected exception while parsing XML") from e

	@staticmethod
	def _validate_errorcode(errorcode: int, errormessage: str) -> None:
		if errorcode == 0:
			return

		raise SoapCodeError("Soap error code non 0", errorcode=errorcode, errormessage=errormessage)

	@property
	def timestamp(self) -> typing.Optional[int]:
		return self._timestamp

	@property
	def errorcode(self) -> typing.Optional[int]:
		return self._errorcode

	@property
	def errormessage(self) -> typing.Optional[str]:
		return self._errormessage

	@property
	def servicestandbymode(self) -> typing.Optional[bool]:
		return self._servicestandbymode
