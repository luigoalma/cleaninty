import typing

from ...nintendowifi import soapenvelopebase
from .types import *

# not for direct use with _xml_xxx_parse
def _parse_attribute_member_impl(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element,
	attr_prefix: bool
) -> AttributePair:
	parent._xml_raise_if_text(element)
	name = parent._xml_element_parse(element, 'urn:AttributeName' if attr_prefix else 'urn:Name', parent._xml_get_str_element)
	value = parent._xml_element_parse(element, 'urn:AttributeValue' if attr_prefix else 'urn:Value', parent._xml_get_str_element)
	return AttributePair(name, value)

def _parse_attribute_member_prefixed(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> AttributePair:
	return _parse_attribute_member_impl(parent, element, True)

def _parse_attribute_member(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> AttributePair:
	return _parse_attribute_member_impl(parent, element, False)

# not for direct use with _xml_xxx_parse
def _xml_get_str_len_limited(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element,
	length: int
) -> str:
	text = parent._xml_get_str_element(parent, element)
	if len(text.encode('utf-8')) > length:
		raise DataProcessingError("str element surpassed length limits")
	return text

def _get_str_limited_parser(
	length: int
) -> typing.Callable[
	[
		soapenvelopebase.SoapEnvelopeBase,
		soapenvelopebase.XML_Element
	],
	str
]:
	def inner(
		parent: soapenvelopebase.SoapEnvelopeBase,
		element: soapenvelopebase.XML_Element
	) -> str:
		return _xml_get_str_len_limited(parent, element, length)
	return inner
