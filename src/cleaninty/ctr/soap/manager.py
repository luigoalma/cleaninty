import hashlib, typing, base64
from enum import IntEnum, unique

from ...nintendowifi.soapsessionmanager import SoapSessionManager
from ..simpledevice import SimpleCtrDevice
from ..title import Title, MediaType
from .. import exception
from .. import regionaldata
from ..ssl import _ssl_certs
from ...connection import Connection
from ..otp import CTCert

__all__ = [
	"ServiceLevel",
	"CtrSoapManager"
]

@unique
class ServiceLevel(IntEnum):
	SHOP = 0,
	SYSTEM = 1

class CtrSoapManager:
	def __init__(self, device: SimpleCtrDevice, nup_agent: bool):
		if not isinstance(device, SimpleCtrDevice):
			raise exception.ClassInitError("Device should be a SimpleCtrDevice")

		self._useragent = f'CTR {"NUP" if nup_agent else "EC"} 040600 Mar 14 2012 13:32:39'
		self._keepalive = True
		self._device = device
		self._appid = None
		self._tin = None
		self._service_urls = {}
		self._service_level = ServiceLevel.SYSTEM if nup_agent else ServiceLevel.SHOP
		self._service_standby = False
		self._ivs_sync_flag = False

		self._connection = Connection()

		self._service_urls['ecs'] = 'https://ecs.c.shop.nintendowifi.net/ecs/services/ECommerceSOAP'
		self._service_urls['ias'] = 'https://ias.c.shop.nintendowifi.net/ias/services/IdentityAuthenticationSOAP'
		self._service_urls['cas'] = 'https://cas.c.shop.nintendowifi.net/cas/services/CatalogingSOAP'
		self._service_urls['nus'] = 'https://nus.c.shop.nintendowifi.net/nus/services/NetUpdateSOAP'

		self._overrides = {}

	def set_app_and_tin(self, appid: typing.Optional[typing.SupportsInt] = None, tin: typing.Optional[typing.SupportsInt] = None):
		if appid is not None:
			appid = int(appid)

		if tin is not None:
			tin = int(tin)

		if (appid and appid < 0) or (tin and tin < 0):
			return exception.DataProcessingError("Expecting positive appid and tin")

		self._appid = appid
		self._tin = tin

	def sleep_with_rng_curve(
		self,
		sleep_min_time: typing.Union[int, float],
		rng_multiplier: typing.Union[int, float] = 1
	) -> None:
		self._device.sleep_with_rng_curve(sleep_min_time, rng_multiplier)

	def get_connection(self) -> Connection:
		return self._connection

	def set_keepalive(self, toggle: bool) -> None:
		self._keepalive = bool(toggle)

	def set_service_standby(self, status: bool) -> None:
		self._service_standby = bool(status)

	def set_ivs_sync_flag(self, status: bool) -> None:
		self._ivs_sync_flag = bool(status)

	def register_account(
		self,
		status: str,
		st_token: str,
		account_id: int,
		country: str,
		ext_account_id: typing.Optional[str] = None,
		device_code: typing.Optional[str] = None,
		register_expired: bool = False
	) -> None:
		if self._service_level == ServiceLevel.SYSTEM:
			return
		if not isinstance(status, str) or not isinstance(st_token, str) or not isinstance(account_id, int) or not isinstance(country, str):
			raise exception.DataProcessingError("Invalid type for status, st_token, account_id or country")
		if status == 'U':
			raise exception.DataProcessingError("Can't register with an unregister, use unregister_account instead")
		last_ivs = self._device._ecommerce_info.get('last_ivs', None) if self.account_id is not None and self.account_id == account_id else None
		ecommerce_info = {
			'st_token': st_token,
			'wt_token': hashlib.md5(st_token.encode('ascii')).hexdigest(),
			'account_id': account_id,
			'account_status': status,
			'register_expired': register_expired,
			'last_ivs': last_ivs
		}
		if ext_account_id:
			ecommerce_info['ext_account_id'] = ext_account_id
		if device_code:
			ecommerce_info['device_code'] = device_code
		self.country_change(country)
		self.drop_account()
		self._device.update_ecommerce(ecommerce_info)

	def unregister_account(self) -> None:
		if self._service_level == ServiceLevel.SYSTEM:
			return
		self._device.update_ecommerce({'account_status': 'U'})

	def drop_account(self) -> None:
		if self._service_level == ServiceLevel.SYSTEM:
			return
		self._device.drop_ecommerce()

	def ap_sign(self, title_id: typing.SupportsInt, data: typing.SupportsBytes) -> typing.Tuple[bytes, bytes]:
		return self._device.ap_sign(title_id, data)

	def region_change(
		self,
		region: regionaldata.RegionType,
		country: typing.Optional[regionaldata.CountryType] = None,
		language: typing.Optional[regionaldata.LanguageType] = None
	) -> None:
		self._device.region_change(region, country, language)
		self.clear_all_overrides()
		self.drop_account()

	def country_change(
		self,
		country: regionaldata.CountryType
	) -> None:
		region = regionaldata.Country.get_region_by_country(country)
		if region != regionaldata.Region.get_region(self._device.region):
			self.region_change(region, country)
		else:
			self._device.country_change(country)
		self.clear_country_override()

	def language_change(
		self,
		language: typing.Optional[regionaldata.LanguageType] = None
	) -> None:
		self._device.language_change(language)
		self.clear_language_override()

	def set_region_override(self, region: regionaldata.RegionType) -> None:
		_region = regionaldata.Region.get_region_str(region)
		if _region is None:
			raise exception.DataProcessingError("Invalid region override")
		self._overrides['region'] = _region

	def set_country_override(self, country: regionaldata.CountryType) -> None:
		_country = regionaldata.Country.get_country_str(country)
		if _country is None:
			raise exception.DataProcessingError("Invalid country override")
		self._overrides['country'] = _country

	def set_language_override(self, language: typing.Optional[regionaldata.LanguageType]) -> None:
		_language = regionaldata.Language.get_language_str(language)
		if _language is None and language is not None:
			raise exception.DataProcessingError("Invalid language override")
		self._overrides['language'] = _language

	def clear_region_override(self) -> None:
		if 'region' in self._overrides.keys():
			del self._overrides['region']

	def clear_country_override(self) -> None:
		if 'country' in self._overrides.keys():
			del self._overrides['country']

	def clear_language_override(self) -> None:
		if 'language' in self._overrides.keys():
			del self._overrides['language']

	def clear_all_overrides(self) -> None:
		self._overrides.clear()

	def get_overrides_copy(self) -> typing.Dict[str, typing.Optional[str]]:
		return self._overrides.copy()

	def load_overrides_copy(self, overrides: typing.Dict[str, typing.Optional[str]]) -> None:
		o = self.get_overrides_copy()
		try:
			region = overrides.get('region', None)
			country = overrides.get('country', None)
			language = overrides.get('language', None)
			if region is not None:
				self.set_region_override(region)
			else:
				self.clear_region_override()
			if country is not None:
				self.set_country_override(country)
			else:
				self.clear_country_override()
			if 'language' in overrides.keys():
				self.set_language_override(language)
			else:
				self.clear_language_override()
		except:
			self._overrides = o
			raise

	def commit_overrides(self) -> None:
		_region = self._overrides.get('region', None)
		_country = self._overrides.get('country', None)
		_language = self._overrides.get('language', None)

		if _region is None and _country is None and _language is None:
			self.clear_all_overrides()
			return

		# country takes priority, as wrong country settings cause registers on wrong regions on real SOAP register
		if _country is not None:
			self.country_change(_country)
		elif _region is not None:
			self.region_change(_region)

		if _language is not None:
			self.language_change(_language)

		self.clear_all_overrides()

	def is_service_ready(self) -> bool:
		if self._service_level == ServiceLevel.SHOP:
			if self._service_urls.get('ecs', None) and \
				self._service_urls.get('cas', None) and \
				self._service_urls.get('content_prefix', None) and \
				self._service_urls.get('uncached_content_prefix', None) and \
				(self._service_urls.get('ias', None) or self._service_standby):
				return True
		else:
			if self._service_urls.get('nus', None) and \
				self._service_urls.get('system_content_prefix', None) and \
				self._service_urls.get('system_uncached_content_prefix', None):
				return True
		return False

	def get_url_by_identifier(self, name: str) -> typing.Optional[str]:
		return self._service_urls.get(name, None)

	def set_url_by_identifier(self, name: str, url: str) -> None:
		if not isinstance(name, str) or not isinstance(name, str):
			raise exception.DataProcessingError("Excepting str for name and url")

		self._service_urls[name] = url

	def export_ivs(self) -> bytes:
		return self._device.export_ivs()

	def import_ivs(self, ivs: typing.SupportsBytes) -> None:
		self._device.import_ivs(ivs)

	def set_last_sync_ivs(self, ivs: typing.SupportsBytes) -> None:
		self._device._ecommerce_info['last_ivs'] = base64.b64encode(bytes(ivs)).decode('utf-8')

	def titles(self, media: MediaType) -> typing.Iterable[Title]:
		return self._device.titles(media)

	@property
	def last_sync_ivs(self) -> typing.Optional[bytes]:
		ivs = self._device._ecommerce_info.get('last_ivs', None)
		if not ivs:
			return None
		return base64.b64decode(ivs)

	@property
	def should_query_registry(self) -> bool:
		return not self._device.has_ecommerce_info

	@property
	def need_register(self) -> bool:
		"""
		This should be only used if .should_query_registry says False
		True if == U.
		T and R and P are different, should check with other conditional checks.
		"""
		return self.account_status == 'U'

	@property
	def need_account_transfer(self) -> bool:
		"""
		This should be only used if .should_query_registry says False
		True if == P.
		U and R and T are different, should check with other conditional checks.
		"""
		return self.account_status == 'P'

	@property
	def service_level(self) -> ServiceLevel:
		return self._service_level

	@property
	def is_time_emu_enabled(self) -> bool:
		return self._device.time_padding_emu

	@property
	def service_standby(self) -> bool:
		return self._service_standby

	@property
	def ivs_sync_flag(self) -> bool:
		return self._ivs_sync_flag

	@property
	def is_msed_signed(self) -> bool:
		return self._device.msed.lfcs.is_signed

	@property
	def ec_version(self) -> str:
		return 'EC 4.6.0 Mar 14 2012 13:32:39'

	@property
	def ext_account_id(self) -> typing.Optional[str]:
		return self._device._ecommerce_info.get('ext_account_id', None)

	@property
	def device_code(self) -> typing.Optional[str]:
		return self._device._ecommerce_info.get('device_code', None)

	@property
	def ct_cert(self) -> bytes:
		return self._device.ct_cert

	@property
	def ct_cert_full(self) -> CTCert:
		return self._device.ct_cert_full

	@property
	def device_id(self) -> int:
		return self._device.device_id | (4 << 32)

	@property
	def message_id_step(self) -> int:
		return self._device.boot_time_ms

	@property
	def has_tokens(self) -> bool:
		return True if self.st_token else False

	@property
	def st_token(self) -> typing.Optional[str]:
		return self._device._ecommerce_info.get('st_token', None)

	@property
	def wt_token(self) -> typing.Optional[str]:
		return self._device._ecommerce_info.get(
			'wt_token',
			hashlib.md5(self.st_token.encode('ascii')).hexdigest() if self.has_tokens else None
		)

	@property
	def account_id(self) -> typing.Optional[int]:
		return self._device._ecommerce_info.get('account_id', None)

	@property
	def account_status(self) -> typing.Optional[str]:
		return self._device._ecommerce_info.get('account_status', None)

	@property
	def register_expired(self) -> bool:
		return self._device._ecommerce_info.get('register_expired', False)

	@property
	def application_id(self) -> typing.Optional[int]:
		return self._appid

	@property
	def tin(self) -> typing.Optional[int]:
		return self._tin

	@property
	def age(self) -> typing.Optional[int]:
		return None # stub for now

	@property
	def region(self) -> typing.Optional[str]:
		return self._device.region if 'region' not in self._overrides.keys() else self._overrides['region']

	@property
	def country(self) -> typing.Optional[str]:
		return self._device.country if 'country' not in self._overrides.keys() else self._overrides['country']

	@property
	def language(self) -> typing.Optional[str]:
		return self._device.language if 'language' not in self._overrides.keys() else self._overrides['language']

	@property
	def serial_no(self) -> str:
		return self._device.serial_no

	@property
	def user_agent(self) -> str:
		return self._useragent

	@property
	def keepalive(self) -> bool:
		return self._keepalive

	@property
	def ssl_cert_path(self) -> typing.Optional[str]:
		return _ssl_certs._ca_id_path(3)

	@property
	def ssl_cli_cert_paths(self) -> typing.Optional[typing.Tuple[str, str]]:
		return _ssl_certs._client_cert_path_tuple(self._device.is_dev)

SoapSessionManager.register(CtrSoapManager)
