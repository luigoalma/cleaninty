import typing, base64
from xml.etree.ElementTree import Element as XML_Element

from .exception import CleanintyExceptionBase

__all__ = [
	"XmlParseHelper",
	"XMLParseError",
	"XML_Element"
]

class XMLParseError(CleanintyExceptionBase):
	"""General XML parse error"""

class XmlParseHelper:
	_xml_response_namespaces: typing.Dict[str, str] = {}

	@staticmethod
	def _xml_raise_if_any_subelement(element: XML_Element) -> None:
		if element.find('./{*}*') is not None:
			raise XMLParseError("Subelements found where they are not wanted")

	@staticmethod
	def _xml_raise_if_text(element: XML_Element) -> None:
		if element.text is not None:
			raise XMLParseError("Element with unexpected text")

	@staticmethod
	def _xml_get_element(
		parent: 'XmlParseHelper',
		element: XML_Element
	) -> XML_Element:
		return element

	@staticmethod
	def _xml_get_str_element(
		parent: 'XmlParseHelper',
		element: XML_Element
	) -> str:
		parent._xml_raise_if_any_subelement(element)
		if element.text is None:
			return ''
		return element.text

	@staticmethod
	def _xml_get_base64_element(
		parent: 'XmlParseHelper',
		element: XML_Element
	) -> bytes:
		text = parent._xml_get_str_element(parent, element)
		return base64.b64decode(text + '===')

	# to not call directly
	@staticmethod
	def _internal__xml_get_int_element_impl(
		parent: 'XmlParseHelper',
		element: XML_Element,
		base: int = 10,
		allowed_min: typing.Optional[int] = None,
		allowed_max: typing.Optional[int] = None
	) -> int:
		parent._xml_raise_if_any_subelement(element)
		var = int(element.text, base) if element.text is not None else 0

		if allowed_min is not None and allowed_max is not None:
			allowed_min, allowed_max = min(allowed_min, allowed_max), max(allowed_min, allowed_max)

		if (allowed_min is not None and var < allowed_min) or \
			(allowed_max is not None and var > allowed_max):
			raise XMLParseError("Desired int boundary was surpassed")

		return var

	@staticmethod
	def _get_xml_int_parser(
		base: int,
		allowed_min: typing.Optional[int] = None,
		allowed_max: typing.Optional[int] = None
	) -> typing.Callable[
		[
			'XmlParseHelper',
			XML_Element
		],
		int
	]:
		@staticmethod
		def inner(
			parent: 'XmlParseHelper',
			element: XML_Element
		) -> int:
			return XmlParseHelper._internal__xml_get_int_element_impl(
				parent, element, base, allowed_min, allowed_max
			)
		return inner

	_xml_get_int_element = _get_xml_int_parser(10)
	_xml_get_int_base16_element = _get_xml_int_parser(16)

	_xml_get_s8_element = _get_xml_int_parser(10, -1<<7, (1<<7)-1)
	_xml_get_u8_element = _get_xml_int_parser(10, 0, (1<<8)-1)
	_xml_get_s8_base16_element = _get_xml_int_parser(16, -1<<7, (1<<7)-1)
	_xml_get_u8_base16_element = _get_xml_int_parser(16, 0, (1<<8)-1)

	_xml_get_s16_element = _get_xml_int_parser(10, -1<<15, (1<<15)-1)
	_xml_get_u16_element = _get_xml_int_parser(10, 0, (1<<16)-1)
	_xml_get_s16_base16_element = _get_xml_int_parser(16, -1<<15, (1<<15)-1)
	_xml_get_u16_base16_element = _get_xml_int_parser(16, 0, (1<<16)-1)

	_xml_get_s32_element = _get_xml_int_parser(10, -1<<31, (1<<31)-1)
	_xml_get_u32_element = _get_xml_int_parser(10, 0, (1<<32)-1)
	_xml_get_s32_base16_element = _get_xml_int_parser(16, -1<<31, (1<<31)-1)
	_xml_get_u32_base16_element = _get_xml_int_parser(16, 0, (1<<32)-1)

	_xml_get_s64_element = _get_xml_int_parser(10, -1<<63, (1<<63)-1)
	_xml_get_u64_element = _get_xml_int_parser(10, 0, (1<<64)-1)
	_xml_get_s64_base16_element = _get_xml_int_parser(16, -1<<63, (1<<63)-1)
	_xml_get_u64_base16_element = _get_xml_int_parser(16, 0, (1<<64)-1)

	def _xml_element_parse(
		self,
		element: XML_Element,
		tagname: str,
		parser: typing.Callable[
			[
				'XmlParseHelper',
				XML_Element
			],
			typing.Any
		],
		optional: bool = False
	) -> typing.Any:
		element = element.find('./{0}'.format(tagname), self._xml_response_namespaces)

		if element is None and not optional:
			raise XMLParseError("Non-optional element not found: {0}".format(tagname))
		elif element is None:
			return None

		return parser(self, element)

	def _xml_multi_element_parse(
		self,
		element: XML_Element,
		tagname: str,
		parser: typing.Callable[
			[
				'XmlParseHelper',
				XML_Element
			],
			typing.Any
		],
		optional: bool = False
	) -> typing.Any:
		_iter = element.iterfind('./{0}'.format(tagname), self._xml_response_namespaces)

		i = None
		values = []
		for i, j in enumerate(_iter):
			values.append(parser(self, j))

		if i is None and not optional:
			raise XMLParseError("Non-optional element not found: {0}".format(tagname))
		elif i is None:
			return None

		return values

	def _xml_multi_element_parse_ret_none(
		self,
		element: XML_Element,
		tagname: str,
		parser: typing.Callable[
			[
				'XmlParseHelper',
				XML_Element
			],
			None
		],
		optional: bool = False
	) -> bool:
		_iter = element.iterfind('./{0}'.format(tagname), self._xml_response_namespaces)

		i = None
		for i, j in enumerate(_iter):
			parser(self, j)

		if i is None and not optional:
			raise XMLParseError("Non-optional element not found: {0}".format(tagname))

		return i is not None # let us know if we got something at least
