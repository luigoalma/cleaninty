import base64, typing

from ...nintendowifi import soapenvelopebase
from .manager import CtrSoapManager
from ..exception import ClassInitError, DataProcessingError
from .exception import OperationError, CTRExceptionBase
from ..title import Title
from ._common_parsers import _parse_attribute_member, _get_str_limited_parser
from .types import AttributePair, AttributeFilterEx, AttributeOrdering, CatalogContentSizes, AmountCurrencyPair
from .types import ContentLimits, ContentItemPrice, ContentRating, CasContentIndexes, CasListResult

#TODO:
# - ListContentSetGroups

__all__ = [
	"GetContentSizes",
	"GetCountryAttributes",
	"GetCountryMigrateAttributes",
	"ListCashReplenishAmounts",
	"ListECardItems",
	"ListTitlesEx",
	"ListContentSetsEx",
	"ListItems"
]

def _xml_get_contentsize(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> CatalogContentSizes:
	text = parent._xml_get_str_element(parent, element)
	split = text.split(',', 3) # i expect 2 commas, but 3 lets me see if too many
	if len(split) != 3:
		raise DataProcessingError("Not enough or too many commas on ContentSize!")
	return CatalogContentSizes(int(split[0], 16), int(split[1]), int(split[2]))

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
	def countryattributes(self) -> typing.Iterable[AttributePair]:
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
			get_capped_str = _get_str_limited_parser(31)
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

# for some SOAPs, code base is the same
class _SharedListingBase(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		soap_action_name: str,
		result_urn_name: str,
		list_offset: int,
		list_limit: int,
		is_ext: bool,
		title_ids: typing.Iterable[int] = [], # I expect it not empty but yeah.
		attributes: typing.Iterable[str] = [],
		attribute_filters: typing.Iterable[AttributePair] = [], # if not is_ext
		extended_attribute_filters: typing.Iterable[AttributeFilterEx] = [], # if is_ext
		order_attributes: typing.Optional[AttributeOrdering] = None, # if is_ext
		additional_attribute_filters: typing.Iterable[AttributePair] = [], # soap specific
		additional_soap_tags: typing.Iterable[typing.Tuple[str,str]] = [] # soap specific
	):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.CAS, soap_action_name, ctrsoapmanager, False, True)

		self._write_tag('ListResultOffset', list_offset)
		self._write_tag('ListResultLimit', list_limit)

		for i in attributes:
			self._write_tag('Attributes', i)

		for i in additional_attribute_filters:
			self._push_tag('AttributeFilters')
			self._write_tag('Name', i.name)
			self._write_tag('Value', i.value)
			self._pop_tag()

		if not is_ext:
			for i in attribute_filters:
				self._push_tag('AttributeFilters')
				self._write_tag('Name', i.name)
				self._write_tag('Value', i.value)
				self._pop_tag()
		else:
			for i in extended_attribute_filters:
				self._push_tag('AttributeFiltersEx')
				self._write_tag('FilterType', i.filter_type)
				self._write_tag('DataType', i.data_type)
				self._write_tag('Name', i.name)
				for j in i.values:
					self._write_tag('Value', j)
				self._pop_tag()
			if order_attributes:
				self._push_tag('OrderByAttribute')
				self._write_tag('OrderByType', order_attributes.order_by_type)
				self._write_tag('DataType', order_attributes.data_type)
				self._write_tag('Name', order_attributes.name)
				self._pop_tag()

		for i in additional_soap_tags:
			self._write_tag(i[0], i[1])

		for i in title_ids:
			self._write_tag('TitleId', f"{int(i):016X}")

		ret = self._send(ctrsoapmanager.get_url_by_identifier('cas'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._list_results_total_size = self._xml_element_parse(response, 'urn:ListResultTotalSize', self._xml_get_int_element)
			self._results = self._xml_multi_element_parse(response, f'urn:{result_urn_name}', self._result_parser, True)
			self._results = tuple(self._results) if self._results is not None else tuple()
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@classmethod
	def _result_parser(
		cls,
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	):
		parent._xml_raise_if_text(element)
		titleid = parent._xml_element_parse(element, 'urn:TitleId', parent._xml_get_u64_base16_element)
		contents = parent._xml_multi_element_parse(element, 'urn:Contents', cls._content_parser, True)
		attributes = parent._xml_multi_element_parse(element, 'urn:Attributes', _parse_attribute_member, True)
		ratings = parent._xml_multi_element_parse(element, 'urn:Ratings', cls._rating_parser, True)
		prices = parent._xml_multi_element_parse(element, 'urn:Prices', cls._price_parser, True)
		return CasListResult(titleid, contents, attributes, ratings, prices)

	@staticmethod
	def _content_parser(
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	) -> CasContentIndexes:
		parent._xml_raise_if_text(element)
		# Contents parser is very odd about consistency, so I'll try to take data as much as I can
		titleincluded = parent._xml_element_parse(element, 'urn:TitleIncluded', parent._xml_get_bool_element, True)
		contentindexes = parent._xml_multi_element_parse(element, 'urn:ContentIndex', parent._xml_get_u16_element, True)
		return CasContentIndexes(titleincluded, contentindexes)

	@staticmethod
	def _rating_parser(
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	) -> ContentRating:
		parent._xml_raise_if_text(element)
		name = parent._xml_element_parse(element, 'urn:Name', parent._xml_get_str_element)
		rating = parent._xml_element_parse(element, 'urn:Rating', parent._xml_get_str_element)
		age = parent._xml_element_parse(element, 'urn:Age', parent._xml_get_s32_element)
		descriptors = parent._xml_element_parse(element, 'urn:Descriptors', parent._xml_get_str_element)
		return ContentRating(name, rating, age, descriptors)

	@staticmethod
	def _price_parser(
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	) -> ContentItemPrice:
		parent._xml_raise_if_text(element)
		itemid = parent._xml_element_parse(element, 'urn:ItemId', parent._xml_get_s32_element)
		price = parent._xml_element_parse(element, 'urn:Price', parent._price_value_parser)
		limits = parent._xml_element_parse(element, 'urn:Limits', parent._limit_parser)
		licensekind = parent._xml_element_parse(element, 'urn:LicenseKind', parent._xml_get_str_element)
		return ContentItemPrice(itemid, price, limits, licensekind)

	@staticmethod
	def _price_value_parser(
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	) -> AmountCurrencyPair:
		parent._xml_raise_if_text(element)
		get_capped_str = _get_str_limited_parser(31)
		amount = parent._xml_element_parse(element, 'urn:Amount', get_capped_str)
		currency = parent._xml_element_parse(element, 'urn:Currency', get_capped_str)
		return AmountCurrencyPair(amount, currency)

	@staticmethod
	def _limit_parser(
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	) -> ContentLimits:
		parent._xml_raise_if_text(element)
		limits = parent._xml_element_parse(element, 'urn:Limits', parent._xml_get_u32_element)
		limitkind = parent._xml_element_parse(element, 'urn:LimitKind', _get_str_limited_parser(4))
		return ContentLimits(limits, limitkind)

	@property
	def list_results_total_size(self) -> int:
		return self._list_results_total_size

	@property
	def results(self) -> typing.Iterable[CasListResult]:
		return self._results

class ListECardItems(_SharedListingBase):
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		list_offset: int,
		list_limit: int,
		ecard_identifier: str,
		title_ids: typing.Iterable[int] = [],
		attributes: typing.Iterable[str] = [],
		attribute_filters: typing.Iterable[AttributePair] = []
	):
		ecard_identifier = str(ecard_identifier)
		if len(ecard_identifier.encode('utf-8')) >= 0x40:
			raise ClassInitError("ECard Identifier must not surpass 63 bytes encoded to utf-8")

		additional_tags = (
			('ECardIdentifier', ecard_identifier),
			('ECardIdentifierKind', 'ECardTypeCode')
		)

		super().__init__(
			ctrsoapmanager,
			'ListECardItems',
			'Items',
			list_offset,
			list_limit,
			False,
			title_ids,
			attributes,
			attribute_filters=attribute_filters,
			additional_soap_tags=additional_tags
		)

class ListTitlesEx(_SharedListingBase):
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		list_offset: int,
		list_limit: int,
		title_ids: typing.Iterable[int] = [],
		attributes: typing.Iterable[str] = [],
		extended_attribute_filters: typing.Iterable[AttributeFilterEx] = [],
		order_attributes: typing.Optional[AttributeOrdering] = None
	):
		super().__init__(
			ctrsoapmanager,
			'ListTitlesEx',
			'Titles',
			list_offset,
			list_limit,
			True,
			title_ids,
			attributes,
			extended_attribute_filters=extended_attribute_filters,
			order_attributes=order_attributes
		)

class ListContentSetsEx(_SharedListingBase):
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		list_offset: int,
		list_limit: int,
		title_ids: typing.Iterable[int] = [],
		attributes: typing.Iterable[str] = [],
		extended_attribute_filters: typing.Iterable[AttributeFilterEx] = [],
		order_attributes: typing.Optional[AttributeOrdering] = None
	):
		super().__init__(
			ctrsoapmanager,
			'ListContentSetsEx',
			'Contents',
			list_offset,
			list_limit,
			True,
			title_ids,
			attributes,
			extended_attribute_filters=extended_attribute_filters,
			order_attributes=order_attributes
		)

class ListItems(_SharedListingBase):
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		list_offset: int,
		list_limit: int,
		title_ids: typing.Iterable[int] = [],
		attributes: typing.Iterable[str] = [],
		attribute_filters: typing.Iterable[AttributePair] = []
	):
		additional_attribute_filters = (
			AttributePair('TitleType', 'CTR_TKT'),
			AttributePair('TitleKind', 'SERVICE')
		)

		super().__init__(
			ctrsoapmanager,
			'ListItems',
			'Items',
			list_offset,
			list_limit,
			False,
			title_ids,
			attributes,
			attribute_filters=attribute_filters,
			additional_attribute_filters=additional_attribute_filters
		)
