# a more quickly put together wrapper for nnid/act stuff
# Thanks zeroskill for extra information on ACT

import typing, base64
import defusedxml.ElementTree as ET
from ..xml_helper import XmlParseHelper, XMLParseError, XML_Element

from .simpledevice import SimpleCtrDevice
from ..connection import Connection, SimpleDownloadBuffer
from .title import Title, MediaType
from .secureinfo import SecureInfo
from . import regionaldata
from .exception import ClassInitError, DataProcessingError, CTRExceptionBase
from .ssl import _ssl_certs
from .constants import _load_act_secrets, _act_cli_data

__all__ = [
	"ActSimpleObj",
	"ActEmptyResponse",
	"ActIgnoredContentResponse",
	"ActErrorElement",
	"CommunicationError",
	"XMLError"
]

_load_act_secrets()

class CommunicationError(CTRExceptionBase):
	"""General communication exception"""

class XMLError(CTRExceptionBase):
	"""General xml exception"""

_base_url = 'https://account.nintendo.net/v1/api'

_nver_tids = (
	(
		0x000400db00016202,
		0x000400db00016302,
		0x000400db00016102,
		None,
		0x000400db00016402,
		0x000400db00016502,
		0x000400db00016602
	),
	(
		0x000400db20016202,
		0x000400db20016302,
		0x000400db20016102,
		None,
		None,
		0x000400db20016502,
		None
	)
)

class ActErrorElement:
	cause: typing.Optional[str] = None
	code: typing.Optional[int] = None
	message: typing.Optional[str] = None

	@property
	def is_malformed(self) -> bool:
		return self.code is None or self.message is None

	@staticmethod
	def _xml_get_error_element(
		parent: XmlParseHelper,
		element: XML_Element
	) -> 'ActErrorElement':
		error = ActErrorElement()

		# code and message are not optional for a correct error message, act ignores cause however
		error.cause = parent._xml_element_parse(element, 'cause', parent._xml_get_str_element, True)
		error.code = parent._xml_element_parse(element, 'code', parent._xml_get_int_element, True)
		error.message = parent._xml_element_parse(element, 'message', parent._xml_get_str_element, True)

		return error

class ActResponseBase(XmlParseHelper):
	def __init__(self, xml_string: typing.Union[str, bytes]):
		self._xml_response = xml_string

		if not len(xml_string):
			self._xml_root = None
			self._errors = tuple()
			self._had_errors = False
			return

		try:
			self._xml_root = ET.fromstring(xml_string)

			if self._xml_root.tag != 'errors':
				self._errors = tuple()
				self._had_errors = False
				return

			self._had_errors = True

			error_list = self._xml_multi_element_parse(self._xml_root, 'error', ActErrorElement._xml_get_error_element, True)
			self._errors = tuple(error_list) if error_list else tuple()
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise XMLParseError("Unexpected exception while parsing XML") from e

		@property
		def errors(self) -> typing.Iterable[ActErrorElement]:
			return self._errors

		@property
		def had_errors(self) -> bool:
			return self._had_errors

class ActEmptyResponse(ActResponseBase):
	def __init__(self, xml_string: typing.Union[str, bytes]):
		super().__init__(xml_string)

		if self._xml_root:
			raise DataProcessingError("Unexpected response data!")

class ActIgnoredContentResponse(ActResponseBase):
	def __init__(self, xml_string: typing.Union[str, bytes]):
		super().__init__(xml_string)

class ActSimpleObj:
	def __init__(
		self,
		device: SimpleCtrDevice,
		title: Title
	):
		if not isinstance(device, SimpleCtrDevice):
			raise ClassInitError("Expected SimpleCtrDevice for ActSimpleObj")

		if not isinstance(title, Title):
			raise ClassInitError("Expected title to be Title object")

		# at least a few cases where i'd not expect title ids from in normal scenarios
		if not Title.is_ctr(title) or Title.is_ctrtwl(title) \
			or Title.is_ctrdlc(title) or Title.is_ctrupdate(title):
			raise ClassInitError("Unexpected title id")

		self._device = device
		region = regionaldata.Region.get_region(device.region)
		if region is None:
			raise ClassInitError("Invalid region")

		nver_tid = _nver_tids[device.is_n3ds][region]
		if nver_tid is None:
			raise ClassInitError("Invalid region")

		ntitles = device.titles(MediaType.NAND)
		i = ntitles.index(nver_tid)
		if i < 0:
			raise ClassInitError("NVER was not found on device object")

		self._nver = ntitles[i]
		self._title = title

	def _model_select(self) -> typing.Literal['CTR', 'SPR', 'FTR', 'KTR', 'RED', 'JAN']:
		model = self._device.model_override
		if model is not None:
			return model

		# CFG handles this some way, but I have not seen 100% how
		# one thing is clear, returns some value that ACT then converts to these things
		# if value is not in range, does 3DS-%u format into a buffer
		# but I dont know what makes CFG return the values that it does asides maybe using SN as reference
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
		_s = dev_sn_firstletters if self._device.is_dev else retail_sn_firstletters
		try:
			i = _s.index(self._device.serial_no[0])
		except ValueError:
			i = 3 if self._device.is_n3ds else 0
		return model_names.get(i, 'CTR')

	def _create_connection(self, url: str):
		_id = _act_cli_data['CLIENT_ID']
		_secret = _act_cli_data['CLIENT_SECRET']
		if _id is None and _secret is None:
			_load_act_secrets()
			_id = _act_cli_data['CLIENT_ID']
			_secret = _act_cli_data['CLIENT_SECRET']
			if _id is None and _secret is None:
				raise DataProcessingError("Missing ACT secrets!")

		conn = Connection()
		conn.set_url(url)
		conn.set_cainfo(_ssl_certs._ca_id_path(3))
		conn.set_cli_cert(*_ssl_certs._client_cert_path_tuple(self._device.is_dev))
		conn.set_header('X-Nintendo-Platform-ID', '0')
		conn.set_header('X-Nintendo-Device-Type', '1' if self._device.is_dev else '2')
		conn.set_header('X-Nintendo-Device-ID', f'{self._device.device_id}')
		conn.set_header('X-Nintendo-Serial-Number', f'{self._device.serial_no}')
		conn.set_header('X-Nintendo-System-Version', f'{self._nver.version:04X}')
		region = regionaldata.Region.get_region(self._device.region)
		region = 0 if region is None else (1 << int(region))
		conn.set_header('X-Nintendo-Region', f'{region}')
		conn.set_header('X-Nintendo-Country', self._device.country)
		conn.set_header('Accept-Language', self._device.language)
		conn.set_header('X-Nintendo-Client-ID', _id)
		conn.set_header('X-Nintendo-Client-Secret', _secret)
		conn.set_header('Accept', '*/*')
		conn.set_header('X-Nintendo-API-Version', '0100')
		conn.set_header('X-Nintendo-FPD-Version', '0000')
		conn.set_header('X-Nintendo-Environment', 'D1' if self._device.is_dev else 'L1')
		conn.set_header('X-Nintendo-Title-ID', f'{self._title.id:016X}')
		conn.set_header('X-Nintendo-Unique-ID', f'{((self._title.id >> 8) & 0xFFFFF):05X}')
		conn.set_header('X-Nintendo-Application-Version', f'{self._title.version_major:04X}') # its actually remaster version, but my only good guess without downloading ncch is this
		conn.set_header('X-Nintendo-Device-Model', self._model_select())
		conn.set_header('X-Nintendo-Device-Cert', base64.b64encode(self._device.ct_cert).decode('utf-8'))

		return conn

	def devices_current_migrations_commit(self) -> typing.Tuple[int, ActEmptyResponse]:
		buf = SimpleDownloadBuffer()

		conn = self._create_connection(_base_url + '/devices/@current/migrations/commit')
		conn.set_header('Content-type', 'application/xml')
		conn.set_customrequest('POST')
		conn.set_write_function(buf.write)

		ret = conn.perform()

		res = ActEmptyResponse(buf.get())
		return (ret, res)

	# act receives an operator, here I just hardset ReserveTransfer
	def devices_current_migrations(
		self,
		*,
		delete: bool = True,
		serialnumber: typing.Optional[str] = None, # target, non optional if delete is false
		deviceid: typing.Optional[typing.SupportsInt] = None # target, non optional if delete is false
	) -> typing.Tuple[int, typing.Union[ActEmptyResponse, ActIgnoredContentResponse]]:
		if not delete:
			serialnumber = SecureInfo.validate_serial(serialnumber)
			deviceid = 0 if deviceid is None else int(deviceid)

			if not serialnumber:
				raise DataProcessingError("Invalid serial number")

			if not 0 < deviceid < 0xFFFFFFFF:
				raise DataProcessingError("Invalid device id")

			msg  =  '<?xml version="1.0" encoding="UTF-8"?>'
			msg +=  '<person_migration><new_platform_id>0</new_platform_id>'
			msg += f'<new_serial_number>{serialnumber}</new_serial_number>'
			msg += f'<new_device_id>{deviceid}</new_device_id>'
			msg +=  '<operator>ReserveTransfer</operator></person_migration>'

		buf = SimpleDownloadBuffer()

		conn = self._create_connection(_base_url + '/devices/@current/migrations')

		if delete:
			conn.set_customrequest('DELETE')
		else:
			conn.set_header('Content-type', 'application/xml')
			conn.set_post_data(msg)

		conn.set_write_function(buf.write)

		ret = conn.perform()

		if delete:
			res = ActIgnoredContentResponse(buf.get())
		else:
			res = ActEmptyResponse(buf.get())
		return (ret, res)
