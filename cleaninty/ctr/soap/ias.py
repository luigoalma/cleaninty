import base64, typing

from ...nintendowifi import soapenvelopebase
from .manager import CtrSoapManager
from ..exception import ClassInitError, DataProcessingError
from .exception import OperationError, CTRExceptionBase
from ..movablesed import MovableSed
from ..regionaldata import Country, CountryType
from ._common_parsers import _parse_attribute_member_prefixed

# no IAS commands left to add

__all__ = [
	"GetChallenge",
	"GetRegistrationInfo",
	"Register",
	"Unregister",
	"AccountTransfer",
	"MoveAccount",
	"SetIVSData",
	"GetIVSData",
	"ReportIVSSync",
	"SetCountry",
	"SetExternalAccount",
	"DeleteExternalAccount",
	"GetAccountAttributesByProfile"
]

class GetChallenge(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'GetChallenge', ctrsoapmanager, False, True)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._challenge = self._xml_element_parse(response, 'urn:Challenge', self._xml_get_int_element)
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def challenge(self) -> int:
		return self._challenge

class GetRegistrationInfo(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, challenge: int):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		if not isinstance(challenge, int):
			raise ClassInitError("Challenge value must be an int returned from GetChallenge soap, and not a reuse")

		signed_message_block = '<Challenge>{0}</Challenge>'.format(challenge)

		signature_data = ctrsoapmanager.ap_sign(0x0004013000002c02, signed_message_block.encode('utf-8'))

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'GetRegistrationInfo', ctrsoapmanager, True, True)

		self._write_tag('DeviceCert', base64.b64encode(ctrsoapmanager.ct_cert).decode('utf-8'))
		self._write_tag('Signature', base64.b64encode(signature_data[1]).decode('utf-8'))
		self._write_tag('CertChain', base64.b64encode(signature_data[0]).decode('utf-8'))
		self._write_tag('Challenge', challenge)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()

		if self.errorcode == 901: # 'IAS - Device Id is not registered'
			self._is_registered = False
			self._accountid = None
			self._devicetoken = None
			self._devicetokenexpired = None
			self._country = None
			self._extaccountid = None
			self._devicecode = None
			return
		else:
			self._is_registered = True # unless other error, which _validate_errorcode will catch

		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._accountid = self._xml_element_parse(response, 'urn:AccountId', self._xml_get_int_element)
			self._devicetoken = self._xml_element_parse(response, 'urn:DeviceToken', self._xml_get_str_element)
			self._devicetokenexpired = self._xml_element_parse(response, 'urn:DeviceTokenExpired', self._xml_get_bool_element, True)
			self._country = self._xml_element_parse(response, 'urn:Country', self._xml_get_str_element)
			self._extaccountid = self._xml_element_parse(response, 'urn:ExtAccountId', self._xml_get_str_element, True)
			self._devicecode = self._xml_element_parse(response, 'urn:DeviceCode', self._xml_get_str_element, True)
			if self._devicetokenexpired is None:
				self._devicetokenexpired = False
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def accountid(self) -> typing.Optional[int]:
		return self._accountid

	@property
	def devicetoken(self) -> typing.Optional[str]:
		return self._devicetoken

	@property
	def devicetokenexpired(self) -> bool:
		return self._devicetokenexpired

	@property
	def country(self) -> typing.Optional[str]:
		return self._country

	@property
	def extaccountid(self) -> typing.Optional[str]:
		return self._extaccountid

	@property
	def devicecode(self) -> typing.Optional[str]:
		return self._devicecode

	@property
	def is_registered(self) -> bool:
		return self._is_registered

class Register(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, challenge: int):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		if not isinstance(challenge, int):
			raise ClassInitError("Challenge value must be an int returned from GetChallenge soap, and not a reuse")

		signed_message_block =  '<Challenge>{0}</Challenge>'.format(challenge)
		signed_message_block += '<SerialNumber>{0}</SerialNumber>'.format(ctrsoapmanager.serial_no)
		signed_message_block += '<Country>{0}</Country>'.format(ctrsoapmanager.country)
		signed_message_block += '<RegisterRegion>{0}</RegisterRegion>'.format(ctrsoapmanager.region)
		signed_message_block += '<Language>{0}</Language>'.format(ctrsoapmanager.language)

		signature_data = ctrsoapmanager.ap_sign(0x0004013000002c02, signed_message_block.encode('utf-8'))

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'Register', ctrsoapmanager, True, True)

		self._write_tag('DeviceCert', base64.b64encode(ctrsoapmanager.ct_cert).decode('utf-8'))
		self._write_tag('SerialNumber', ctrsoapmanager.serial_no)
		self._write_tag('RegisterRegion', ctrsoapmanager.region)
		self._write_tag('Signature', base64.b64encode(signature_data[1]).decode('utf-8'))
		self._write_tag('CertChain', base64.b64encode(signature_data[0]).decode('utf-8'))
		self._write_tag('Challenge', challenge)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._accountid = self._xml_element_parse(response, 'urn:AccountId', self._xml_get_int_element)
			self._devicetoken = self._xml_element_parse(response, 'urn:DeviceToken', self._xml_get_str_element)
			self._devicetokenexpired = self._xml_element_parse(response, 'urn:DeviceTokenExpired', self._xml_get_bool_element, True)
			self._country = self._xml_element_parse(response, 'urn:Country', self._xml_get_str_element)
			self._extaccountid = self._xml_element_parse(response, 'urn:ExtAccountId', self._xml_get_str_element, True)
			self._devicecode = self._xml_element_parse(response, 'urn:DeviceCode', self._xml_get_str_element, True)
			if self._devicetokenexpired is None:
				self._devicetokenexpired = False
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def accountid(self) -> int:
		return self._accountid

	@property
	def devicetoken(self) -> str:
		return self._devicetoken

	@property
	def devicetokenexpired(self) -> bool:
		return self._devicetokenexpired

	@property
	def country(self) -> str:
		return self._country

	@property
	def extaccountid(self) -> typing.Optional[str]:
		return self._extaccountid

	@property
	def devicecode(self) -> typing.Optional[str]:
		return self._devicecode

	@property
	def is_registered(self) -> bool:
		return True

class Unregister(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, challenge: int):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		if not isinstance(challenge, int):
			raise ClassInitError("Challenge value must be an int returned from GetChallenge soap, and not a reuse")

		signed_message_block =  '<Challenge>{0}</Challenge>'.format(challenge)
		signed_message_block += '<SerialNumber>{0}</SerialNumber>'.format(ctrsoapmanager.serial_no)

		signature_data = ctrsoapmanager.ap_sign(0x0004013000002c02, signed_message_block.encode('utf-8'))

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'Unregister', ctrsoapmanager, True, True)

		self._write_tag('DeviceCert', base64.b64encode(ctrsoapmanager.ct_cert).decode('utf-8'))
		self._write_tag('SerialNumber', ctrsoapmanager.serial_no)
		self._write_tag('Signature', base64.b64encode(signature_data[1]).decode('utf-8'))
		self._write_tag('CertChain', base64.b64encode(signature_data[0]).decode('utf-8'))
		self._write_tag('Challenge', challenge)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

class AccountTransfer(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, challenge: int):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		if not isinstance(challenge, int):
			raise ClassInitError("Challenge value must be an int returned from GetChallenge soap, and not a reuse")

		signed_message_block =  '<Challenge>{0}</Challenge>'.format(challenge)
		signed_message_block += '<SerialNumber>{0}</SerialNumber>'.format(ctrsoapmanager.serial_no)
		signed_message_block += '<Country>{0}</Country>'.format(ctrsoapmanager.country)
		signed_message_block += '<RegisterRegion>{0}</RegisterRegion>'.format(ctrsoapmanager.region)
		signed_message_block += '<Language>{0}</Language>'.format(ctrsoapmanager.language)

		signature_data = ctrsoapmanager.ap_sign(0x0004013000002c02, signed_message_block.encode('utf-8'))

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'AccountTransfer', ctrsoapmanager, True, True)

		self._write_tag('DeviceCert', base64.b64encode(ctrsoapmanager.ct_cert).decode('utf-8'))
		self._write_tag('SerialNumber', ctrsoapmanager.serial_no)
		self._write_tag('RegisterRegion', ctrsoapmanager.region)
		self._write_tag('Signature', base64.b64encode(signature_data[1]).decode('utf-8'))
		self._write_tag('CertChain', base64.b64encode(signature_data[0]).decode('utf-8'))
		self._write_tag('Challenge', challenge)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._accountid = self._xml_element_parse(response, 'urn:AccountId', self._xml_get_int_element)
			self._devicetoken = self._xml_element_parse(response, 'urn:DeviceToken', self._xml_get_str_element)
			self._devicetokenexpired = self._xml_element_parse(response, 'urn:DeviceTokenExpired', self._xml_get_bool_element, True)
			self._country = self._xml_element_parse(response, 'urn:Country', self._xml_get_str_element)
			self._extaccountid = self._xml_element_parse(response, 'urn:ExtAccountId', self._xml_get_str_element, True)
			self._devicecode = self._xml_element_parse(response, 'urn:DeviceCode', self._xml_get_str_element, True)
			if self._devicetokenexpired is None:
				self._devicetokenexpired = False
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def accountid(self) -> int:
		return self._accountid

	@property
	def devicetoken(self) -> str:
		return self._devicetoken

	@property
	def devicetokenexpired(self) -> bool:
		return self._devicetokenexpired

	@property
	def country(self) -> str:
		return self._country

	@property
	def extaccountid(self) -> typing.Optional[str]:
		return self._extaccountid

	@property
	def devicecode(self) -> typing.Optional[str]:
		return self._devicecode

class MoveAccount(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(
		self,
		ctrsoapmanager: CtrSoapManager,
		target_device_id: int,
		target_account_id: int,
		target_device_token: str,
		check_only: bool
	):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'MoveAccount', ctrsoapmanager, True, True)

		self._write_tag('TargetDeviceId', str(int(target_device_id)))
		self._write_tag('TargetAccountId', str(int(target_account_id)))
		self._write_tag('TargetDeviceToken', str(target_device_token))
		if check_only:
			self._write_tag('CheckOnly', 'true')

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		# on something like NIM, errorcode is parsed as type of reason of why we can or cannot transfer
		# for now, raise error
		self._validate_errorcode(self.errorcode, self.errormessage)

class SetIVSData(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, ivs: typing.SupportsBytes):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'SetIVSData', ctrsoapmanager, True, True)

		self._write_tag('IVSData', base64.b64encode(bytes(ivs)).decode('utf-8'))

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

class GetIVSData(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'GetIVSData', ctrsoapmanager, True, True)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			# originally, this is considered "optional", error still rises, not really "optional"
			self._ivsdata = self._xml_element_parse(response, 'urn:IVSData', self._xml_get_base64_element, True)
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def ivsdata(self) -> typing.Optional[bytes]:
		return self._ivsdata

class ReportIVSSync(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'ReportIVSSync', ctrsoapmanager, True, True)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

class SetCountry(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, countrycode: CountryType):
		countrycode = Country.get_country_str(countrycode)

		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		if countrycode is None: # NIM accepts any string, however, I do not
			raise ClassInitError("Invalid country code")

		_overrides = ctrsoapmanager.get_overrides_copy()

		try:
			ctrsoapmanager.set_country_override(countrycode)

			super().__init__(soapenvelopebase.SoapSubNames.IAS, 'SetCountry', ctrsoapmanager, True, True)

			self._write_tag('CountryCode', countrycode)

			ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
			if ret != 200:
				raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

			response_parse = self._initiate_response_parse()
			self._validate_errorcode(self.errorcode, self.errormessage)

			ctrsoapmanager.commit_overrides()
		except:
			ctrsoapmanager.load_overrides_copy(_overrides)
			raise

class SetExternalAccount(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, ext_account_id: str, password: str):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'SetExternalAccount', ctrsoapmanager, True, True)

		self._write_tag('ExtAccountId', ext_account_id)
		self._write_tag('NewPassword', password)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

class DeleteExternalAccount(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, ext_account_id: str):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'DeleteExternalAccount', ctrsoapmanager, True, False)

		self._write_tag('ExtAccountId', ext_account_id)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)

class GetAccountAttributesByProfile(soapenvelopebase.SoapEnvelopeBase):
	@soapenvelopebase.ObjectTimingEmuHelper(0.9, 0.125)
	def __init__(self, ctrsoapmanager: CtrSoapManager, profile: str):
		if not isinstance(ctrsoapmanager, CtrSoapManager):
			raise ClassInitError("Expected CtrSoapManager")

		super().__init__(soapenvelopebase.SoapSubNames.IAS, 'GetAccountAttributesByProfile', ctrsoapmanager, False, False)

		self._write_tag('Profile', profile)

		ret = self._send(ctrsoapmanager.get_url_by_identifier('ias'))
		if ret != 200:
			raise OperationError("Bad HTTP response or connection error, ret = {0}".format(ret))

		response_parse = self._initiate_response_parse()
		self._validate_errorcode(self.errorcode, self.errormessage)
		try:
			response = response_parse[1]
			self._accountattribits = self._xml_element_parse(response, 'urn:AccountAttribits', self._xml_get_int_element, True)
			self._accountattribits = 0 if self._accountattribits is None else self._accountattribits
			if self._accountattribits < 0 or self._accountattribits > 0xffffffffffffffff:
				raise DataProcessingError("Out of range account attribits")
			self._accountattributes = self._xml_multi_element_parse(response, 'urn:AccountAttributes', _parse_attribute_member_prefixed, True)
			self._accountattributes = tuple(self._accountattributes) if self._accountattributes is not None else tuple()
		except CTRExceptionBase:
			raise
		except Exception as e:
			raise soapenvelopebase.XMLParseError("Unexpected exception while parsing XML") from e

	@property
	def accountattribits(self) -> int:
		return self._accountattribits

	@property
	def accountattributes(self) -> typing.Iterator[typing.Tuple[str, str]]:
		return self._accountattributes
