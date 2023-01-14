import base64, typing

from ...nintendowifi import soapenvelopebase
from .manager import CtrSoapManager
from ..exception import ClassInitError, DataProcessingError
from .exception import OperationError, CTRExceptionBase
from ..title import Title
from ._common_parsers import _parse_attribute_member

#TODO:
# - ListContentSetGroups
# ugh, I really dont like the next ones
# - ListECardItems
# - ListTitlesEx
# - ListContentSetsEx
# - ListItems

__all__ = [
	"GetContentSizes",
	"GetCountryAttributes",
	"GetCountryMigrateAttributes",
	"ListCashReplenishAmounts"
]

class CatalogContentSizes:
	def __init__(
		self,
		content_id: int,
		content_index: int,
		size: int
	):
		if not 0 <= content_id <= 0xffffffff or \
			not 0 <= content_index < 65536 or \
			not 0 <= size <= 0xffffffffffffffff:
			raise DataProcessingError("Invalid content size information!")

		self._id = content_id
		self._index = content_index
		self._size = size

	@property
	def id(self) -> int:
		return self._id

	@property
	def index(self) -> int:
		return self._index

	@property
	def size(self) -> int:
		return self._size

def _xml_get_contentsize(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> CatalogContentSizes:
	text = parent._xml_get_str_element(parent, element)
	split = text.split(',', 3) # i expect 2 commas, but 3 lets me see if too many
	if len(split) != 3:
		raise DataProcessingError("Not enough or too many commas on ContentSize!")
	return CatalogContentSizes(int(split[0], 16), int(split[1]), int(split[2]))

# not for direct use with _xml_xxx_parse
def _xml_get_str_len_limited(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element,
	length: int
) -> str:
	text = parent._xml_get_str_element(parent, element)
	if len(text) > length:
		raise DataProcessingError("str element surpassed length limits")
	return text

class GetContentSizes(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		title: Title,
		content_indexes: typing.Iterable[typing.SupportsInt],
		resort: bool = False
	):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		if not isinstance(title, Title):
			raise ClassInitError("Expected Title for title")

		# there's also a pre-requisite to use ctrsoapmanager.set_app_and_tin to set application id and tin, its a must!

		super().__init__(soapenvelopebase.SoapSubNames.CAS, 'GetContentSizes', ctrsoapmanager, False, False)

		self._write_tag('TitleId', f"{title.id:016X}")
		self._write_tag('TitleVersion', f"{title.version}")

		count = 0
		indexes = []
		for i in content_indexes:
			i = int(i)
			if not 0 <= i < 65536:
				raise DataProcessingError("Content indexes are an u16 value")
			indexes.append(f"{i}")
			if len(indexes) == 100:
				self._write_tag('ContentIndex', ','.join(indexes))
				indexes.clear()
			count += 1
		if indexes:
			self._write_tag('ContentIndex', ','.join(indexes))

		del indexes

		ret = self._send(ctrsoapmanager.get_url_by_identifier('cas'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._contentsizes = self._xml_multi_element_parse(response, 'urn:ContentSize', _xml_get_contentsize)
			self._contentsizes = tuple(self._contentsizes) if self._contentsizes is not None else tuple()
			self._tmdsize = self._xml_element_parse(response, 'urn:TMDSize', self._xml_get_int_element)
			if not 0 <= self._tmdsize < 0xffffffff:
				raise DataProcessingError("Invalid TMD Size!")
			self._maxcontentindex = self._xml_element_parse(response, 'urn:MaxContentIndex', self._xml_get_int_element)
			if not 0 <= self._maxcontentindex < 65536:
				raise DataProcessingError("Out of range max content index!")
			# it's expected to return same amount of content sizes, no more no less, but I won't error here
			self._got_all = count == len(self._contentsizes)
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

		if resort:
			self._contentsizes = tuple(sorted(self._contentsizes, key=lambda x: x.index))

	@property
	def contentsizes(self) -> typing.Iterable[CatalogContentSizes]:
		return self._contentsizes

	@property
	def tmdsize(self) -> int:
		return self._tmdsize
	
	@property
	def maxcontentindex(self) -> int:
		return self._maxcontentindex

	@property
	def got_all(self) -> bool:
		return self._got_all # may be False if indexes list was empty, returns all of them if none specified on Soap

class GetCountryAttributes(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.CAS, 'GetCountryAttributes', ctrsoapmanager, False, False)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('cas'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._countryattribits = self._xml_element_parse(response, 'urn:CountryAttribits', self._xml_get_int_element, True)
			self._countryattribits = 0 if self._countryattribits is None else self._countryattribits
			if self._countryattribits < 0 or self._countryattribits > 0xffffffffffffffff:
				raise DataProcessingError("Out of range country attribits")
			self._countryattributes = self._xml_multi_element_parse(response, 'urn:CountryAttributes', _parse_attribute_member, True)
			self._countryattributes = tuple(self._countryattributes) if self._countryattributes is not None else tuple()
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def countryattribits(self) -> int:
		return self._countryattribits

	@property
	def countryattributes(self) -> typing.Iterator[typing.Tuple[str, str]]:
		return self._countryattributes

class GetCountryMigrateAttributes(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.CAS, 'GetCountryMigrateAttributes', ctrsoapmanager, False, False)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('cas'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._enablemigratetitle = self._xml_element_parse(response, 'urn:EnableMigrateTitle', self._xml_get_bool_element)
			self._enablemigrateaccount = self._xml_element_parse(response, 'urn:EnableMigrateAccount', self._xml_get_bool_element)
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def enablemigratetitle(self) -> bool:
		return self._enablemigratetitle

	@property
	def enablemigrateaccount(self) -> bool:
		return self._enablemigrateaccount

class ListCashReplenishAmounts(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.CAS, 'ListCashReplenishAmounts', ctrsoapmanager, False, True)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('cas'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			get_capped_str = lambda x,y: _xml_get_str_len_limited(x, y, 31)
			self._currency = self._xml_element_parse(response, 'urn:Currency', get_capped_str)
			self._mincash = self._xml_element_parse(response, 'urn:MinCash', get_capped_str)
			self._maxcashbalance = self._xml_element_parse(response, 'urn:MaxCashBalance', get_capped_str)
			self._listamounts = self._xml_multi_element_parse(response, 'urn:ListAmounts', get_capped_str, True)
			self._listamounts = tuple(self._listamounts) if self._listamounts is not None else tuple()
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def currency(self) -> str:
		return self._currency

	@property
	def mincash(self) -> str:
		return self._mincash

	@property
	def maxcashbalance(self) -> str:
		return self._maxcashbalance

	@property
	def listamounts(self) -> typing.Iterable[str]:
		return self._listamounts
