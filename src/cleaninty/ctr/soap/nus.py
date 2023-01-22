import base64, typing, random

from ...nintendowifi.soapsessionmanager import SoapSessionManager
from ...nintendowifi import soapenvelopebase
from .manager import CtrSoapManager
from ..exception import ClassInitError
from .exception import OperationError, CTRExceptionBase
from ...connection import Connection
from ..ssl import _ssl_certs
from ..title import Title, MediaType
from .._sys_titles import o3ds_sys_titles, n3ds_sys_titles
from .. import regionaldata
from ..ticket import Ticket
from ..certificate import Certificate

# no NUS commands left to add

__all__ = [
	"CtrStubManager",
	"GetSystemTitleHash",
	"GetSystemUpdate",
	"GetSystemCommonETicket",
	"StubCallError"
]

class StubCallError(CTRExceptionBase):
	"""Stub called function"""

class CtrStubManager:
	def __init__(
		self,
		is_n3ds: bool,
		randomize: bool = False,
		region: regionaldata.RegionType = regionaldata.Region.JPN,
		is_dev: bool = False
	):
		self._device_id = (4 << 32) | (random.randint(0, 0x7FFFFFFF) if randomize else 0) | (0x80000000 if is_n3ds else 0)

		self._region = regionaldata.Region.get_region(region)
		if self._region is None:
			self._region = regionaldata.Region.JPN
		elif self._region == regionaldata.Region.AUS:
			self._region = regionaldata.Region.EUR
		self._country = random.choice(
			regionaldata.Country.get_region_country_list(self._region)
		) if randomize else (
			regionaldata.Country.JP,
			regionaldata.Country.US,
			regionaldata.Country.GB,
			None,
			regionaldata.Country.CN,
			regionaldata.Country.KR,
			regionaldata.Country.TW
		)[self._region]
		self._language = regionaldata.Language.get_region_language_list(self._region)[0]

		self._sys_titles = (n3ds_sys_titles if is_n3ds else o3ds_sys_titles)[self._region]
		self._sys_titles = tuple() if self._sys_titles is None else self._sys_titles

		self._serial = random.choice(('Y', 'Q', 'N') if is_n3ds else ('C', 'S', 'A')) if randomize else ('Y' if is_n3ds else 'C')
		self._serial += ('JF', 'W', 'EH', None, 'CF', 'KF', 'TF')[self._region]
		self._serial += f'{(random.choice((1,4,7,9)) * 10000000) + random.randint(0, 9999999)}' if randomize else '10000001'

		self._region = self._region.get_region_str(self._region)
		self._country = self._country.get_country_str(self._country)
		self._language = self._language.get_language_str(self._language)

		self._is_dev = bool(is_dev)

		self._connection = Connection()

	def sleep_with_rng_curve(
		self,
		sleep_min_time: typing.Union[int, float],
		rng_multiplier: typing.Union[int, float] = 1
	):
		pass

	def get_connection(self) -> Connection:
		return self._connection

	def set_service_standby(self, status: bool) -> None:
		raise StubCallError("standby mode is an ecs operation, manager is a nus stub")

	@property
	def is_time_emu_enabled(self) -> bool:
		return False

	@property
	def service_standby(self) -> bool:
		raise StubCallError("standby mode is an ecs operation, manager is a nus stub")

	@property
	def device_id(self) -> int:
		return self._device_id

	@property
	def message_id_step(self) -> int:
		return 0

	@property
	def has_tokens(self) -> bool:
		raise StubCallError("tokens don't apply on nus, manager is a nus stub")

	@property
	def st_token(self) -> typing.Optional[str]:
		raise StubCallError("tokens don't apply on nus, manager is a nus stub")

	@property
	def wt_token(self) -> typing.Optional[str]:
		raise StubCallError("tokens don't apply on nus, manager is a nus stub")

	@property
	def account_id(self) -> typing.Optional[int]:
		raise StubCallError("account ids don't apply on nus, manager is a nus stub")

	@property
	def account_status(self) -> typing.Optional[str]:
		raise StubCallError("account status don't apply on nus, manager is a nus stub")

	@property
	def application_id(self) -> typing.Optional[int]:
		raise StubCallError("application id applies to ecs and cas, manager is a nus stub")

	@property
	def tin(self) -> typing.Optional[int]:
		raise StubCallError("tin applies to ecs and cas, manager is a nus stub")

	@property
	def age(self) -> typing.Optional[int]:
		raise StubCallError("age doesn't apply to nus, manager is a nus stub")

	@property
	def region(self) -> typing.Optional[str]:
		return self._region

	@property
	def country(self) -> typing.Optional[str]:
		return self._country

	@property
	def language(self) -> typing.Optional[str]:
		return self._language

	@property
	def serial_no(self) -> str:
		return self._serial

	@property
	def user_agent(self) -> str:
		return 'CTR NUP 040600 Mar 14 2012 13:32:39'

	@property
	def keepalive(self) -> bool:
		return True

	@property
	def ssl_cert_path(self) -> typing.Optional[str]:
		return _ssl_certs._ca_id_path(3)

	@property
	def ssl_cli_cert_paths(self) -> typing.Optional[typing.Tuple[str, ...]]:
		return _ssl_certs._client_cert_path_tuple(self._is_dev)

	def titles(self, media: MediaType) -> typing.Iterable[Title]:
		return self._sys_titles if media == MediaType.NAND else tuple()

	def get_url_by_identifier(self, name: str) -> typing.Optional[str]:
		return 'https://nus.c.shop.nintendowifi.net/nus/services/NetUpdateSOAP' if name == 'nus' else None

SoapSessionManager.register(CtrStubManager)

def _xml_get_titleversion_element(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> typing.Tuple[
	int, int, typing.Optional[int], typing.Optional[int], typing.Optional[int]
]:
	parent._xml_raise_if_text(element)
	titleid = parent._xml_element_parse(element, 'urn:TitleId', parent._xml_get_int_base16_element)
	version = parent._xml_element_parse(element, 'urn:Version', parent._xml_get_int_element)
	fssize = parent._xml_element_parse(element, 'urn:FsSize', parent._xml_get_int_element, True)
	tiksize = parent._xml_element_parse(element, 'urn:TicketSize', parent._xml_get_int_element, True)
	tmdsize = parent._xml_element_parse(element, 'urn:TMDSize', parent._xml_get_int_element, True)
	return (titleid, version, fssize, tiksize, tmdsize)

class GetSystemTitleHash(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: typing.Union[CtrSoapManager, CtrStubManager]):
		if not isinstance(ctrsoapmanager, CtrSoapManager) and not isinstance(ctrsoapmanager, CtrStubManager):
			raise ClassInitError("Expected CtrSoapManager or CtrStubManager")

		super().__init__(soapenvelopebase.SoapSubNames.NUS, 'GetSystemTitleHash', ctrsoapmanager, False, True, False)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('nus'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._titlehash = self._xml_element_parse(response, 'urn:TitleHash', self._xml_get_str_element)
			if len(self._titlehash) != 32:
				raise soapenvelopebase.XMLParseError("length of TitleHash != 32 bytes")
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def titlehash(self) -> str:
		return self._titlehash

class GetSystemUpdate(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: typing.Union[CtrSoapManager, CtrStubManager]):
		if not isinstance(ctrsoapmanager, CtrSoapManager) and not isinstance(ctrsoapmanager, CtrStubManager):
			raise ClassInitError("Expected CtrSoapManager or CtrStubManager")

		super().__init__(soapenvelopebase.SoapSubNames.NUS, 'GetSystemUpdate', ctrsoapmanager, False, True, False)

		for i in ctrsoapmanager.titles(MediaType.NAND):
			if not Title.is_ctranysys(i.id):
				continue
			self._push_tag('TitleVersion')
			self._write_tag('TitleId', i.id)
			self._write_tag('Version', i.version)
			self._pop_tag()

		ret = self._send(ctrsoapmanager.get_url_by_identifier('nus'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			# normal parser only gets title versions and hash, but I get all that I observed appear in a response
			self._contextprefixurl = self._xml_element_parse(response, 'urn:ContentPrefixURL', self._xml_get_str_element, True)
			self._uncachedcontextprefixurl = self._xml_element_parse(response, 'urn:UncachedContentPrefixURL', self._xml_get_str_element, True)
			self._titles = self._xml_multi_element_parse(response, 'urn:TitleVersion', _xml_get_titleversion_element, True)
			self._titles = tuple(self._titles) if self._titles is not None else None
			self._uploadauditdata = self._xml_element_parse(response, 'urn:UploadAuditData', self._xml_get_str_element, True)
			self._titlehash = self._xml_element_parse(response, 'urn:TitleHash', self._xml_get_str_element, self._titles is None)
			if self._titlehash is not None and len(self._titlehash) != 32:
				raise soapenvelopebase.XMLParseError("length of TitleHash != 32 bytes")
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def contextprefixurl(self) -> typing.Optional[str]:
		return self._contextprefixurl

	@property
	def uncachedcontextprefixurl(self) -> typing.Optional[str]:
		return self._uncachedcontextprefixurl

	@property
	def titles(self) -> typing.Iterator[
		typing.Tuple[
			int, int, typing.Optional[int], typing.Optional[int], typing.Optional[int]
		]
	]:
		return self._titles

	@property
	def uploadauditdata(self) -> typing.Optional[str]:
		return self._uploadauditdata

	@property
	def titlehash(self) -> typing.Optional[str]:
		return self._titlehash

class GetSystemCommonETicket(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, titleids: typing.Iterable[typing.SupportsInt]):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.NUS, 'GetSystemCommonETicket', ctrsoapmanager, False, False, False)

		count = 0

		for i in titleids:
			self._write_tag('TitleId', f"{int(i):016X}")
			count += 1

		ret = self._send(ctrsoapmanager.get_url_by_identifier('nus'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

		try:
			response = response_parse[1]
			self._cetks = self._xml_multi_element_parse(response, 'urn:CommonETicket', lambda x,y: Ticket(self._xml_get_base64_element(x, y)), True)
			self._cetks = tuple(self._cetks) if self._cetks is not None else tuple()
			self._certs = self._xml_multi_element_parse(response, 'urn:Certs', lambda x,y: Certificate(self._xml_get_base64_element(x, y)), True)
			self._certs = tuple(self._certs) if self._certs is not None else tuple()
			# title ids requested must be == cetks received, but like ecs:AccountGetETickets, I'll ignore it
			self._got_all = count == len(self._cetks)
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def cetks(self) -> typing.Iterator[Ticket]:
		return self._cetks

	@property
	def certs(self) -> typing.Iterator[Certificate]:
		return self._certs

	@property
	def got_all(self) -> bool:
		return self._got_all
