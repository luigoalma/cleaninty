import typing
from collections import OrderedDict

from .._py_ver_fixes import LimitKind_T, LicenseKind_T
from ..exception import DataProcessingError

# common
class AttributePair:
	def __init__(self, name: str, value: str):
		self._name = str(name)
		self._value = str(value)

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} name={self._name!r} value={self._value!r}>"

	def asdict(self):
		ret = OrderedDict()
		ret['Name'] = self._name
		ret['Value'] = self._value
		return ret

	@property
	def name(self) -> str:
		return self._name

	@property
	def value(self) -> str:
		return self._value

# cas types
class AttributeFilterEx:
	def __init__(
		self,
		filter_type: str,
		data_type: str,
		name: str,
		values: typing.Iterable[str]
	):
		self._filter_type = str(filter_type)
		self._data_type = str(data_type)
		self._name = str(name)
		self._values = tuple(str(i) for i in values)

	@property
	def filter_type(self) -> str:
		return self._filter_type

	@property
	def data_type(self) -> str:
		return self._data_type

	@property
	def name(self) -> str:
		return self._name

	@property
	def values(self) -> typing.Iterable[str]:
		return self._values

class AttributeOrdering:
	def __init__(
		self,
		order_by_type: str,
		data_type: str,
		name: str
	):
		self._order_by_type = order_by_type
		self._data_type = data_type
		self._name = name

	@property
	def order_by_type(self) -> str:
		return self._order_by_type

	@property
	def data_type(self) -> str:
		return self._data_type

	@property
	def name(self) -> str:
		return self._name

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

	def asdict(self):
		ret = OrderedDict()
		ret['Id'] = str(self._id)
		ret['Index'] = str(self._index)
		ret['Size'] = str(self._size)
		return ret

	@property
	def id(self) -> int:
		return self._id

	@property
	def index(self) -> int:
		return self._index

	@property
	def size(self) -> int:
		return self._size

# ecs types
class ETicketInfo:
	def __init__(
		self,
		ticketid: int,
		titleid: int,
		version: int,
		formatversion: int,
		migratecount: int,
		migratelimit: int,
		estimatedsize: int
	):
		self._ticketid = ticketid
		self._titleid = titleid
		self._version = version
		self._formatversion = formatversion
		self._migratecount = migratecount
		self._migratelimit = migratelimit
		self._estimatedsize = estimatedsize

	def asdict(self):
		ret = OrderedDict()
		ret['TicketId'] = str(self._ticketid)
		ret['TitleId'] = f"{self._titleid:016X}"
		ret['Version'] = str(self._version)
		ret['FormatVersion'] = str(self._formatversion)
		ret['MigrateCount'] = str(self._migratecount)
		ret['MigrateLimit'] = str(self._migratelimit)
		ret['EstimatedSize'] = str(self._estimatedsize)
		return ret

	@property
	def ticketid(self) -> int:
		return self._ticketid

	@property
	def titleid(self) -> int:
		return self._titleid

	@property
	def version(self) -> int:
		return self._version

	@property
	def formatversion(self) -> int:
		return self._formatversion

	@property
	def migratecount(self) -> int:
		return self._migratecount

	@property
	def migratelimit(self) -> int:
		return self._migratelimit

	@property
	def estimatedsize(self) -> int:
		return self._estimatedsize

class SavedCardInfo:
	def __init__(
		self,
		cardtype: str,
		expirationmonth: str,
		expirationyear: str,
		maskedcardnumber: str
	):
		if len(cardtype) > 1 or len(expirationmonth) > 2 or \
			len(expirationyear) > 2 or len(maskedcardnumber) < 4:
			raise DataProcessingError("Invalid saved card information!")

		self._cardtype = cardtype
		self._expirationmonth = expirationmonth
		self._expirationyear = expirationyear
		self._maskedcardnumber = maskedcardnumber[-4:]

	def asdict(self):
		ret = OrderedDict()
		ret['CardType'] = str(self._cardtype)
		ret['ExpirationMonthMM'] = str(self._expirationmonth)
		ret['ExpirationYearYY'] = str(self._expirationyear)
		ret['MaskedCardNumber'] = str(self._maskedcardnumber)
		return ret

	@property
	def cardtype(self) -> str:
		return self._cardtype

	@property
	def expirationmonth(self) -> str:
		return self._expirationmonth

	@property
	def expirationyear(self) -> str:
		return self._expirationyear

	@property
	def maskedcardnumber(self) -> str:
		return self._maskedcardnumber

class TransactionInfo:
	def __init__(
		self,
		transactionid: int,
		date: int,
		_type: str
	):
		if not -0x8000000000000000 <= transactionid <= 0x7fffffffffffffff or \
			not -0x8000000000000000 <= date <= 0x7fffffffffffffff or \
			len(_type) > 15:
			raise DataProcessingError("Invalid transaction information!")

		self._transactionid = transactionid
		self._date = date
		self._type = _type

	def asdict(self):
		ret = OrderedDict()
		ret['TransactionId'] = str(self._transactionid)
		ret['Date'] = str(self._date)
		ret['Size'] = self._type
		return ret

	@property
	def transactionid(self) -> int:
		return self._transactionid

	@property
	def date(self) -> int:
		return self._date

	@property
	def type(self) -> str:
		return self._type

# ecs & cas
class AmountCurrencyPair:
	def __init__(self, amount: str, currency: str):
		self._amount = str(amount)
		self._currency = str(currency)

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} amount={self._amount!r} currency={self._currency!r}>"

	def asdict(self):
		ret = OrderedDict()
		ret['Amount'] = self._amount
		ret['Currency'] = self._currency
		return ret

	@property
	def amount(self) -> str:
		return self._amount

	@property
	def currency(self) -> str:
		return self._currency

# ecs & cas
class ContentLimits:
	def __init__(self, limits: int, limitkind: LimitKind_T):
		self._limits = int(limits)
		self._limitkind = str(limitkind)

		if not 0 <= self._limits <= 0xffffffff:
			raise DataProcessingError("Limits go outside range of an u32")

		if len(self._limitkind.encode('utf-8')) > 4:
			raise DataProcessingError("LimitKind cannot be bigger than 4")

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} limits={self._limits!r} limitkind={self._limitkind!r}>"

	def asdict(self):
		ret = OrderedDict()
		ret['Limits'] = str(self._limits)
		ret['LimitKind'] = self._limitkind
		return ret

	@property
	def limits(self) -> int:
		return self._limits

	@property
	def limitkind(self) -> LimitKind_T:
		return self._limitkind

	@property
	def is_limitkind_sane(self) -> bool:
		return self._limitkind in ['PR', 'TR', 'DR', 'SR', 'LR', 'ET']

# cas
class ContentItemPrice:
	def __init__(
		self,
		itemid: int,
		price: AmountCurrencyPair,
		limits: ContentLimits,
		licensekind: LicenseKind_T
	):
		self._itemid = int(itemid)
		self._price = price
		self._limits = limits
		self._licensekind = str(licensekind)

		if not -0x80000000 <= self._itemid <= 0x7fffffff:
			raise DataProcessingError("ItemId go outside range of an s32")

		if not isinstance(self._price, AmountCurrencyPair):
			raise DataProcessingError("Expected AmountCurrencyPair for Price")

		if not isinstance(self._limits, ContentLimits):
			raise DataProcessingError("Expected ContentLimits for Limits")

		if self._licensekind not in ['PERMANENT', 'DEMO', 'TRIAL', 'RENTAL', 'SUBSCRIPT', 'SERVICE']:
			raise DataProcessingError(f"LicenseKind is invalid, got {licensekind}")

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} itemid={self._itemid!r} price={self._price!r} limits={self._limits!r} licensekind={self._licensekind!r}>"

	def asdict(self):
		ret = OrderedDict()
		ret['ItemId'] = str(self._itemid)
		ret['Price'] = self._price.asdict()
		ret['Limits'] = self._limits.asdict()
		ret['LicenseKind'] = self._licensekind
		return ret

	@property
	def itemid(self) -> int:
		return self._itemid

	@property
	def price(self) -> AmountCurrencyPair:
		return self._price

	@property
	def limits(self) -> ContentLimits:
		return self._limits

	@property
	def licensekind(self) -> LicenseKind_T:
		return self._licensekind

# cas
class ContentRating:
	def __init__(
		self,
		name: str,
		rating: str,
		age: int,
		descriptors: str
	):
		self._name = str(name)
		self._rating = str(rating)
		self._age = int(age)
		self._descriptors = str(descriptors)

		if not -0x80000000 <= self._age <= 0x7fffffff:
			raise DataProcessingError("Age go outside range of an s32")

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} name={self._name!r} rating={self._rating!r} age={self._age!r} descriptors={self._descriptors!r}>"

	def asdict(self):
		ret = OrderedDict()
		ret['Name'] = self._name
		ret['Rating'] = self._rating
		ret['Age'] = str(self._age)
		ret['Descriptors'] = self._descriptors
		return ret

	@property
	def name(self) -> str:
		return self._name

	@property
	def rating(self) -> str:
		return self._rating

	@property
	def age(self) -> int:
		return self._age

	@property
	def descriptors(self) -> str:
		return self._descriptors

# cas
class CasContentIndexes:
	def __init__(
		self,
		titleincluded: typing.Optional[bool],
		contentindexes: typing.Optional[typing.Iterable[int]]
	):
		self._titleincluded = bool(titleincluded) if titleincluded is not None else None
		self._contentindexes = tuple(contentindexes) if contentindexes is not None else None

		if self._contentindexes is not None:
			for i in self._contentindexes:
				if not 0 <= i <= 0xffff:
					raise DataProcessingError("ContentIndex go outside range of an u16")

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} titleincluded={self._titleincluded!r} contentindexes={self._contentindexes!r}>"

	def asdict(self):
		ret = OrderedDict()
		ret['TitleIncluded'] = self._titleincluded
		ret['ContentIndex'] = [str(i) for i in self._contentindexes] if self._contentindexes is not None else None
		return ret

	@property
	def titleincluded(self) -> typing.Optional[bool]:
		return self._titleincluded

	@property
	def contentindexes(self) -> typing.Optional[int]:
		return self._contentindex

# cas
class CasListResult:
	def __init__(
		self,
		titleid: int,
		contents: typing.Optional[typing.Iterable[CasContentIndexes]],
		attributes: typing.Optional[typing.Iterable[AttributePair]],
		ratings: typing.Optional[typing.Iterable[ContentRating]],
		prices: typing.Optional[typing.Iterable[ContentItemPrice]]
	):
		self._titleid = int(titleid) if titleid is not None else None
		self._contents = tuple(contents) if contents is not None else None
		self._attributes = tuple(attributes) if attributes is not None else None
		self._ratings = tuple(ratings) if ratings is not None else None
		self._prices = tuple(prices) if prices is not None else None

		if not 0 <= self._titleid <= 0xffffffffffffffff:
			raise DataProcessingError("TitleId go outside range of an u64")

		def check(x, _type):
			if x is not None:
				for i in x:
					if not isinstance(i, _type):
						return False
			return True

		if not check(self._contents, CasContentIndexes):
			raise DataProcessingError("At least one content is not CasContentIndexes")

		if not check(self._attributes, AttributePair):
			raise DataProcessingError("At least one attribute is not AttributePair")

		if not check(self._ratings, ContentRating):
			raise DataProcessingError("At least one rating is not ContentRating")

		if not check(self._prices, ContentItemPrice):
			raise DataProcessingError("At least one price is not ContentItemPrice")

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		foo =  f"<{modname}.{clsname} "
		foo += f"titleid=0x{self._titleid:016X} "
		foo += f"contents={self._contents!r} "
		foo += f"attributes={self._attributes!r} "
		foo += f"ratings={self._ratings!r} "
		foo += f"prices={self._prices!r}>"
		return foo

	def asdict(self):
		ret = OrderedDict()
		ret['TitleId'] = f"{self._titleid:016X}"
		ret['Contents'] = [i.asdict() for i in self._contents] if self._contents is not None else None
		ret['Attributes'] = [i.asdict() for i in self._attributes] if self._attributes is not None else None
		ret['Ratings'] = [i.asdict() for i in self._ratings] if self._ratings is not None else None
		ret['Prices'] = [i.asdict() for i in self._prices] if self._prices is not None else None
		return ret

	@property
	def titleid(self) -> int:
		return self._titleid

	@property
	def contents(self) -> typing.Optional[typing.Iterable[CasContentIndexes]]:
		return self._contents

	@property
	def attributes(self) -> typing.Optional[typing.Iterable[AttributePair]]:
		return self._attributes

	@property
	def ratings(self) -> typing.Optional[typing.Iterable[ContentRating]]:
		return self._ratings

	@property
	def prices(self) -> typing.Optional[typing.Iterable[ContentItemPrice]]:
		return self._prices

# cas
class CasAttributeGroups:
	def __init__(
		self,
		name: str,
		size: int,
	):
		self._name = str(name)
		self._size = int(size)

		if not 0 <= self._size <= 0xffffffff:
			raise DataProcessingError("Size limited to u32")

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} name={self._name!r} size={self._size!r}>"

	def asdict(self):
		ret = OrderedDict()
		ret['Name'] = str(self._name)
		ret['Size'] = int(self._size)
		return ret

	@property
	def name(self) -> str:
		return self._name

	@property
	def size(self) -> int:
		return self._size
