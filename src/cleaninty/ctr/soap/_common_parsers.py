import typing

from ...nintendowifi import soapenvelopebase

# not for direct use with _xml_xxx_parse
def _parse_attribute_member_impl(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element,
	attr_prefix: bool
) -> typing.Tuple[str,str]:
	parent._xml_raise_if_text(element)
	name = parent._xml_element_parse(element, 'urn:AttributeName' if attr_prefix else 'urn:Name', parent._xml_get_str_element)
	value = parent._xml_element_parse(element, 'urn:AttributeValue' if attr_prefix else 'urn:Value', parent._xml_get_str_element)
	return (name, value)

def _parse_attribute_member_prefixed(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> typing.Tuple[str,str]:
	return _parse_attribute_member_impl(parent, element, True)

def _parse_attribute_member(
	parent: soapenvelopebase.SoapEnvelopeBase,
	element: soapenvelopebase.XML_Element
) -> typing.Tuple[str,str]:
	return _parse_attribute_member_impl(parent, element, False)
