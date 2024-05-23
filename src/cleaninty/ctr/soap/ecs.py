import base64, typing, re

from ...nintendowifi import soapenvelopebase
from .manager import CtrSoapManager, ServiceLevel
from ..exception import ClassInitError, DataProcessingError
from .exception import OperationError, CTRExceptionBase
from ..certificate import Certificate
from ..ticket import Ticket
from ._common_parsers import _parse_attribute_member, _get_str_limited_parser, _content_limit_parser
from .types import AttributePair, ETicketInfo, SavedCardInfo, AmountCurrencyPair, ContentLimits, EcsItemPricing, TransactionInfo

#TODO:
# - GetTaxes
# - GetPurchaseInfo
# - GetTaxLocation
# - AccountPurchaseTitle
# - AccountReplenishment

__all__ = [
	"AccountListETicketIds",
	"AccountListPurchaseHistory",
	"AccountGetETicketDetails",
	"AccountGetETickets",
	"AccountCheckBalance",
	"CheckECard",
	"CurrencyAccountsCheckBalance",
	"AccountDeleteTitleETickets",
	"DeleteSavedCard",
	"DownloadExpressETicket",
	"GetAccountStatus",
	"GetStandbyMode",
	"GetWalletInfo",
	"ETicketInfo",
	"SavedCardInfo"
]

def _xml_get_tiv_element(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> typing.Tuple[int,int]:
	text = parent._xml_get_str_element(parent, element)
	match = re.fullmatch("^([0-9]+)\\.([0-9]+)$", text)
	if not match:
		raise soapenvelopebase.XMLParseError("Invalid TIV found")

	return (int(match.group(1), 10), int(match.group(2), 10))

def _xml_get_eticketinfo_element(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> ETicketInfo:
	parent._xml_raise_if_text(element)
	ticketid = parent._xml_element_parse(element, 'urn:TicketId', parent._xml_get_s64_element)
	titleid = parent._xml_element_parse(element, 'urn:TitleId', parent._xml_get_u64_base16_element)
	version = parent._xml_element_parse(element, 'urn:Version', parent._xml_get_s32_element)
	formatversion = parent._xml_element_parse(element, 'urn:FormatVersion', parent._xml_get_s32_element, True)
	formatversion = formatversion if formatversion is not None else 0
	migratecount = parent._xml_element_parse(element, 'urn:MigrateCount', parent._xml_get_s32_element)
	migratelimit = parent._xml_element_parse(element, 'urn:MigrateLimit', parent._xml_get_s32_element)
	estimatedsize = parent._xml_element_parse(element, 'urn:EstimatedSize', parent._xml_get_s32_element, True)
	estimatedsize = estimatedsize if estimatedsize is not None else 0
	return ETicketInfo(ticketid, titleid, version, formatversion, migratecount, migratelimit, estimatedsize)

# not to pass to a _xml_xxx_parse directly
def _xml_get_balance_element(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element,
	optional: bool
) -> typing.Optional[AmountCurrencyPair]:
	parent._xml_raise_if_text(element)
	get_capped_str = _get_str_limited_parser(31)
	amount = parent._xml_element_parse(element, 'urn:Amount', get_capped_str, optional)
	currency = parent._xml_element_parse(element, 'urn:Currency', get_capped_str, optional)
	if amount is None or currency is None:
		return None
	return AmountCurrencyPair(amount, currency)

def _xml_get_saved_card_element(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> SavedCardInfo:
	parent._xml_raise_if_text(element)
	cardtype = parent._xml_element_parse(element, 'urn:CardType', parent._xml_get_str_element)
	expirationmonth = parent._xml_element_parse(element, 'urn:ExpirationMonthMM', parent._xml_get_str_element)
	expirationyear = parent._xml_element_parse(element, 'urn:ExpirationYearYY', parent._xml_get_str_element)
	maskedcardnumber = parent._xml_element_parse(element, 'urn:MaskedCardNumber', parent._xml_get_str_element)
	return SavedCardInfo(cardtype, expirationmonth, expirationyear, maskedcardnumber)

# not to pass to a _xml_xxx_parse
def _parse_service_uris(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element, # that has 'ServiceURLs' in it
	optional: bool
) -> typing.Dict[str,str]:
	uris = {}
	def _parse_uri(
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	) -> None:
		parent._xml_raise_if_text(element)
		name = parent._xml_element_parse(element, 'urn:Name', parent._xml_get_str_element)
		uri = parent._xml_element_parse(element, 'urn:URI', parent._xml_get_str_element)
		_name = {
			'EcsURL': 'ecs',
			'IasURL': 'ias',
			'CasURL': 'cas',
			'NusURL': 'nus',
			'ContentPrefixURL': 'content_prefix',
			'UncachedContentPrefixURL': 'uncached_content_prefix',
			'SystemContentPrefixURL': 'system_content_prefix',
			'SystemUncachedContentPrefixURL': 'system_uncached_content_prefix'
		}.get(name, None)
		if not _name:
			return
		uris[_name] = uri
	parent._xml_multi_element_parse_ret_none(element, 'urn:ServiceURLs', _parse_uri, optional)
	return uris

# not to pass to a _xml_xxx_parse
def _parse_account_attributes(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element, # that has 'AccountAttributes' in it
	optional: bool
) -> typing.Dict[str,typing.Optional[str]]:
	attributes = {}
	def _parse_attribute(
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	) -> None:
		parent._xml_raise_if_text(element)
		name = parent._xml_element_parse(element, 'urn:Name', parent._xml_get_str_element)
		value = parent._xml_element_parse(element, 'urn:Value', parent._xml_get_str_element, True)
		_name = {
			'LOYALTY_LOGIN_NAME': 'LOYALTY_LOGIN_NAME'
		}.get(name, None)
		if not _name:
			return
		attributes[_name] = value
	parent._xml_multi_element_parse_ret_none(element, 'urn:AccountAttributes', _parse_attribute, optional)
	return attributes

def _xml_get_transaction_element_impl(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element,
	short_version: bool
) -> TransactionInfo:
	parent._xml_raise_if_text(element)
	transactionid = parent._xml_element_parse(element, 'urn:TransactionId', parent._xml_get_s64_element)
	date = parent._xml_element_parse(element, 'urn:Date', parent._xml_get_s64_element)
	_type = parent._xml_element_parse(element, 'urn:Type', _get_str_limited_parser(16))
	if short_version:
		return TransactionInfo(transactionid, date, _type)

	totalpaid = parent._xml_element_parse(element, 'urn:TotalPaid', _get_str_limited_parser(32), True)
	currency = parent._xml_element_parse(element, 'urn:Currency', _get_str_limited_parser(32), True)

	def _pricing(
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	) -> EcsItemPricing:
		limits = parent._xml_multi_element_parse(element, 'urn:Limits', _content_limit_parser, True)
		limits = tuple(limits) if limits is not None else tuple()
		# dont know if any more exist, NIM reversal dont show signs of any more objects parsed
		return EcsItemPricing(limits)

	itempricing = parent._xml_multi_element_parse(element, 'urn:ItemPricing', _pricing, True)
	itempricing = tuple(itempricing) if itempricing is not None else tuple()
	titleid = parent._xml_element_parse(element, 'urn:TitleId', parent._xml_get_u64_base16_element, True)
	itemcode = parent._xml_element_parse(element, 'urn:ItemCode', _get_str_limited_parser(20), True)

	referenceid_raw = parent._xml_element_parse(element, 'urn:ReferenceId', _get_str_limited_parser(32), True)
	if referenceid_raw is not None:
		referenceid_raw = referenceid_raw.encode('utf-8')
		if len(referenceid_raw) != 32:
			raise DataProcessingError("Invalid length for ReferenceId")
		# they did a weird conversion, any invalid chars are treated as 0
		referenceid_raw = re.sub(b'[^0-9a-fA-F]', b'0', referenceid_raw)
		# and uneven amount of chars for an hex, drops the last char
		# but we already check if its 32 chars :)
		referenceid = bytes.fromhex(referenceid_raw.decode('ascii'))
	else:
		referenceid = None

	referencevalue = parent._xml_element_parse(element, 'urn:ReferenceValue', parent._xml_get_s64_element, True)
	limits = parent._xml_multi_element_parse(element, 'urn:Limits', _content_limit_parser, True)
	limits = tuple(limits) if limits is not None else tuple()
	# extra stuff unseen on executable binary here, this is from observation of a request response dump
	catalogref = parent._xml_element_parse(element, 'urn:CatalogRef', parent._xml_get_str_element, True)
	itemref = parent._xml_element_parse(element, 'urn:ItemRef', parent._xml_get_int_element, True)
	priceref = parent._xml_element_parse(element, 'urn:PriceRef', parent._xml_get_int_element, True)
	transactionref = parent._xml_element_parse(element, 'urn:TransactionRef', parent._xml_get_int_element, True)

	return TransactionInfo(
		transactionid, date, _type, totalpaid,
		currency, itempricing, titleid, itemcode,
		referenceid, referencevalue, limits, catalogref,
		itemref, priceref, transactionref)

def _xml_get_transaction_element(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> TransactionInfo:
	return _xml_get_transaction_element_impl(parent, element, True)

def _xml_get_full_transaction_element(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> TransactionInfo:
	return _xml_get_transaction_element_impl(parent, element, False)

def _xml_get_titleid_ticketid_pair(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> typing.Tuple[int, int]:
	parent._xml_raise_if_text(element)
	# titleid get checked for, but never checked or stored in actual code
	titleid = parent._xml_element_parse(element, 'urn:TitleId', parent._xml_get_u64_base16_element)
	ticketid = parent._xml_element_parse(element, 'urn:TicketId', parent._xml_get_s64_element)
	return (titleid, ticketid)

class AccountListETicketIds(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'AccountListETicketIds', ctrsoapmanager, True, True)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._tivs = self._xml_multi_element_parse(response, 'urn:TIV', _xml_get_tiv_element, True)
			self._tivs = tuple(self._tivs) if self._tivs is not None else tuple()
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def tivs(self) -> typing.Iterable[typing.Tuple[int, int]]:
		return self._tivs

class AccountListPurchaseHistory(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		begin_date: int, # unix timestamp * 1000
		end_date: int, # unix timestamp * 1000 # max milliseconds allowed reported by server: 4832585298182 
		list_offset: int,
		list_limit: int,
	):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'AccountListPurchaseHistory', ctrsoapmanager, True, True)

		self._write_tag('beginDate', f'{begin_date}')
		self._write_tag('endDate', f'{end_date}')

		self._write_tag('ListResultOffset', list_offset)
		self._write_tag('ListResultLimit', list_limit)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._transactions = self._xml_multi_element_parse(response, f'urn:Transactions', _xml_get_full_transaction_element, True)
			self._transactions = tuple(self._transactions) if self._transactions is not None else tuple()
			self._list_result_total_size = self._xml_element_parse(response, 'urn:ListResultTotalSize', self._xml_get_s64_element)
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def list_result_total_size(self) -> int:
		return self._list_result_total_size

	@property
	def transactions(self) -> typing.Iterable[TransactionInfo]:
		return self._transactions

class AccountGetETicketDetails(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, etickets: typing.Iterable[int]):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'AccountGetETicketDetails', ctrsoapmanager, True, True)

		for i in etickets:
			self._write_tag('TicketIds', i)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._eticketinfos = self._xml_multi_element_parse(response, 'urn:ETicketInfos', _xml_get_eticketinfo_element, True)
			self._eticketinfos = tuple(self._eticketinfos) if self._eticketinfos is not None else tuple()
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def eticketinfos(self) -> typing.Iterable[ETicketInfo]:
		return self._eticketinfos

class AccountGetETickets(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, etickets_ids: typing.Iterable[int]):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'AccountGetETickets', ctrsoapmanager, True, True)

		count = 0

		for i in etickets_ids:
			self._write_tag('TicketId', i)
			count += 1

		self._write_tag('DeviceCert', base64.b64encode(ctrsoapmanager.ct_cert).decode('utf-8'))

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._etickets = self._xml_multi_element_parse(response, 'urn:ETickets', lambda x,y: Ticket(self._xml_get_base64_element(x, y), ctrsoapmanager.ct_cert_full), True)
			self._etickets = tuple(self._etickets) if self._etickets is not None else tuple()
			self._certs = self._xml_multi_element_parse(response, 'urn:Certs', lambda x,y: Certificate(self._xml_get_base64_element(x, y)), True)
			self._certs = tuple(self._certs) if self._certs is not None else tuple()
			# by norm, ticket ids requested must be == etickets received, but here i'll ignore and leave a check field
			self._got_all = count == len(self._etickets)
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def etickets(self) -> typing.Iterable[Ticket]:
		return self._etickets

	@property
	def certs(self) -> typing.Iterable[Certificate]:
		return self._certs

	@property
	def got_all(self) -> bool:
		return self._got_all

class AccountCheckBalance(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'AccountCheckBalance', ctrsoapmanager, False, True)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._balance = self._xml_element_parse(response, 'urn:Balance', lambda x, y: _xml_get_balance_element(x, y, False))
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def balance(self) -> AmountCurrencyPair:
		return self._balance

class CheckECard(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		ecardid: str,
		ecardattributes: typing.Iterable[str]
	):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'CheckECard', ctrsoapmanager, True, True)

		self._write_tag('ECardId', ecardid)
		for i in ecardattributes:
			self._write_tag('ECardAttributes', i)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		if self.errorcode in [14, 15, 903]:
			self._validate_errorcode(self.errorcode, self.errormessage)

		# apparently we still parse not one of those errors stated above
		# but we still keep error

		try:
			response = response_parse[1]
			self._ecardattributes = self._xml_multi_element_parse(response, 'urn:ECardAttributes', _parse_attribute_member, True)
			self._ecardattributes = tuple(self._ecardattributes) if self._ecardattributes is not None else tuple()
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def ecardattributes(self) -> typing.Iterable[AttributePair]:
		return self._ecardattributes

class CurrencyAccountsCheckBalance(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'CurrencyAccountsCheckBalance', ctrsoapmanager, False, True)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._balances = self._xml_multi_element_parse(response, 'urn:Balance', lambda x, y: _xml_get_balance_element(x, y, False), True)
			self._balances = tuple(self._balances) if self._balances is not None else tuple()
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def balances(self) -> typing.Iterable[AmountCurrencyPair]:
		return self._balances

class AccountDeleteTitleETickets(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, titleid: int):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'AccountDeleteTitleETickets', ctrsoapmanager, True, True)

		# normally its just one title, but plural makes me wonder if it supports multiple at once
		self._write_tag('Titles', f'{titleid:016X}')

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

class DeleteSavedCard(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'DeleteSavedCard', ctrsoapmanager, True, True)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

class DownloadExpressETicket(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		itemid: int,
		titleid: int,
		limits: typing.Optional[
			typing.Iterable[
				ContentLimits
			]
		] = None,
		purchasenotes: typing.Optional[str] = None
	):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		if not -0x80000000 <= itemid <= 0x7fffffff:
			raise DataProcessingError("Invalid item id")

		limits = limits if limits else (ContentLimits(0, 'PR'),)

		for i in limits:
			if not isinstance(limits, ContentLimits):
				raise DataProcessingError("At least one limit is not ContentLimits")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'DownloadExpressETicket', ctrsoapmanager, True, False)

		self._write_tag('ItemId', f"{itemid}")
		self._write_tag('TitleId', f"{titleid:016X}")

		for i in limits:
			self._push_tag('Limits')
			self._write_tag('Limits', f"{i.limits}")
			self._write_tag('LimitKind', i.limitkind)
			self._pop_tag()

		self._write_tag('DeviceCert', base64.b64encode(ctrsoapmanager.ct_cert).decode('utf-8'))

		if ctrsoapmanager.age is not None:
			self._write_tag('Age', ctrsoapmanager.age)

		if purchasenotes is not None:
			self._write_tag('PurchaseNotes', purchasenotes)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		if self.errorcode in [14, 15, 903]:
			self._validate_errorcode(self.errorcode, self.errormessage)

		try:
			response = response_parse[1]
			self._transactions = self._xml_multi_element_parse(response, 'urn:Transactions', _xml_get_transaction_element, True)
			self._transactions = tuple(self._transactions) if self._transactions is not None else tuple()
			# ETickets implies multiple, but this one SOAP parses for one, just in case, I'll do multi parse
			self._etickets = self._xml_multi_element_parse(response, 'urn:ETickets', lambda x,y: Ticket(self._xml_get_base64_element(x, y), ctrsoapmanager.ct_cert_full))
			self._etickets = tuple(self._etickets) if self._etickets is not None else tuple()
			self._certs = self._xml_multi_element_parse(response, 'urn:Certs', lambda x,y: Certificate(self._xml_get_base64_element(x, y)), True)
			self._certs = tuple(self._certs) if self._certs is not None else tuple()
			id_pair = self._xml_element_parse(response, 'urn:TitleIdTicketId', _xml_get_titleid_ticketid_pair, True)
			self._titleid = id_pair[0] if id_pair else None
			self._ticketid = id_pair[1] if id_pair else None
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def transactions(self) -> typing.Iterable[TransactionInfo]:
		return self._transactions

	@property
	def etickets(self) -> typing.Iterable[Ticket]:
		return self._etickets

	@property
	def eticket(self) -> Ticket:
		return self._etickets[0]

	@property
	def certs(self) -> typing.Iterable[Certificate]:
		return self._certs

	@property
	def titleid(self) -> typing.Optional[int]:
		return self._titleid

	@property
	def ticketid(self) -> typing.Optional[int]:
		return self._ticketid

class GetAccountStatus(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'GetAccountStatus', ctrsoapmanager, True, True)

		self._write_tag('ECVersion', ctrsoapmanager.ec_version)
		self._write_tag('Locale', f"{ctrsoapmanager.language}_{ctrsoapmanager.country}")
		self._write_tag('ServiceLevel', ctrsoapmanager.service_level.name)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		#some error codes are ignored or parsed different
		#they are best validated after parsing values
		#most error codes are left for the callee to determine what to do

		response_parse = self._initiate_response_parse()

		try:
			response = response_parse[1]
			self._accountid = self._xml_element_parse(response, 'urn:AccountId', self._xml_get_int_element, True) if ctrsoapmanager.service_level == ServiceLevel.SHOP else None
			self._accountstatus = self._xml_element_parse(response, 'urn:AccountStatus', self._xml_get_str_element, True)
			if ctrsoapmanager.service_level == ServiceLevel.SHOP:
				self._balance = self._xml_element_parse(response, 'urn:Balance', lambda x, y: _xml_get_balance_element(x, y, True), True)
				self._eulaversion = self._xml_element_parse(response, 'urn:EulaVersion', self._xml_get_int_element, True)
				self._latesteulaversion = self._xml_element_parse(response, 'urn:LatestEulaVersion', self._xml_get_int_element, True)
				self._country = self._xml_element_parse(response, 'urn:Country', self._xml_get_str_element, True)
				self._region = self._xml_element_parse(response, 'urn:Region', self._xml_get_str_element, True) # Not originally parsed
				self._accountattributes = _parse_account_attributes(self, response, True)
				self._tivs = self._xml_multi_element_parse(response, 'urn:TIV', _xml_get_tiv_element, True)
				self._tivs = tuple(self._tivs) if self._tivs is not None else None
			self._uris = _parse_service_uris(self, response, True)
			self._ivssyncflag = self._xml_element_parse(response, 'urn:IVSSyncFlag', self._xml_get_bool_element, True)
			if self._ivssyncflag is None:
				self._ivssyncflag = False
			self._countryattribits = self._xml_element_parse(response, 'urn:CountryAttribits', self._xml_get_int_element, True) # Not originally parsed
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

		if not self._accountstatus and not self.servicestandbymode:
			raise soapenvelopebase.SoapError("No account status and not in service standby!")

		if not self._is_ready(ctrsoapmanager.service_level == ServiceLevel.SHOP):
			raise soapenvelopebase.SoapError("Soap response did not have all necessary information for the active service level")

		# validate errorcode
		if self.errorcode == 901 and self._accountstatus != 'U':
			raise soapenvelopebase.SoapError("Invalid combination of ErrorCode and AccountStatus")

	def _is_ready(self, is_shop: bool) -> bool:
		if is_shop:
			if self._uris.get('ecs', None) and \
				self._uris.get('cas', None) and \
				self._uris.get('content_prefix', None) and \
				self._uris.get('uncached_content_prefix', None) and \
				(self._uris.get('ias', None) or self.servicestandbymode):
				return True
		else:
			if self._uris.get('nus', None) and \
				self._uris.get('system_content_prefix', None) and \
				self._uris.get('system_uncached_content_prefix', None):
				return True
		return False

	def update_soap_managers_uris(self) -> None:
		if not self._uris:
			return

		for x, y in self._uris.items():
			self._session_manager.set_url_by_identifier(x, y)

	def validate_errorcode(self) -> None:
		self._validate_errorcode(self.errorcode, self.errormessage)

	@property
	def accountid(self) -> typing.Optional[int]:
		return self._accountid

	@property
	def accountstatus(self) -> typing.Optional[str]:
		return self._accountstatus

	@property
	def balance(self) -> typing.Optional[AmountCurrencyPair]:
		return self._balance

	@property
	def eulaversion(self) -> typing.Optional[int]:
		return self._eulaversion

	@property
	def latesteulaversion(self) -> typing.Optional[int]:
		return self._latesteulaversion

	@property
	def country(self) -> typing.Optional[str]:
		return self._country

	@property
	def region(self) -> typing.Optional[str]:
		return self._region

	@property
	def accountattributes(self) -> typing.Optional[typing.Dict[str,typing.Optional[str]]]:
		return self._accountattributes

	@property
	def tivs(self) -> typing.Optional[typing.Iterable[typing.Tuple[int, int]]]:
		return self._tivs

	@property
	def uris(self) -> typing.Optional[typing.Dict[str, str]]:
		return self._uris.copy() if self._uris is not None else None

	@property
	def ivssyncflag(self) -> bool:
		return self._ivssyncflag

	@property
	def countryattribits(self) -> typing.Optional[int]:
		return self._countryattribits

class GetStandbyMode(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'GetStandbyMode', ctrsoapmanager, False, True)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

		# this SOAP gets ServiceStandbyMode and TimeStamp responses mainly, which base already does.

class GetWalletInfo(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.ECS, 'GetWalletInfo', ctrsoapmanager, True, False)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ecs'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

		try:
			response = response_parse[1]
			self._savedcardinfo = self._xml_element_parse(response, 'urn:SavedCreditCardInfo', _xml_get_saved_card_element, True)
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def savedcardinfo(self) -> typing.Optional[SavedCardInfo]:
		return self._savedcardinfo
