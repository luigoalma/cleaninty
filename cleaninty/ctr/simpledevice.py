import json, base64, typing, warnings
from collections import OrderedDict
from struct import pack

from cryptography.hazmat.primitives.asymmetric import ec, utils as crypto_utils
from cryptography.hazmat.primitives import hashes

from .boottimeemu import BootTimeEmu
from .otp import OTP, CTCert
from .apcert import APCert
from .secureinfo import SecureInfo
from .movablesed import MovableSed
from .title import Title, MediaType
from ._sys_titles import o3ds_sys_titles, n3ds_sys_titles
from .exception import ClassInitError, DataProcessingError
from . import regionaldata
from ._py_ver_fixes import CTRModel_T

__all__ = [
	"SimpleCtrDevice"
]

class SimpleCtrDevice:
	"""
	Mostly simple class to simulate basic functionalities and information.
	Specifically:
	 - Boot time
	 - Region, country and language
	 - Serial number
	 - OTP, CTCert, generating and signing with APCerts
	 - Ecommerce
	"""

	def __init__(
		self,
		*,
		json_fp: typing.Optional[typing.TextIO] = None,
		json_file: typing.Optional[str] = None,
		json_string: typing.Optional[str] = None,
		time_padding_emu: bool = True,
		**kwargs
	):
		self._boottime = BootTimeEmu()
		self._time_padding_emu = bool(time_padding_emu) # except boot time, controls padding times

		try:
			if json_fp:
				settings = json.load(json_fp)
			elif json_file:
				with open(json_file, 'r', encoding='utf-8') as file:
					settings = json.load(file)
			else:
				settings = json.loads(json_string)
		except Exception as e:
			raise ClassInitError("Json loading error") from e

		try:
			self._otp = OTP(base64.b64decode(settings['otp'][:0x158]))
			self._ctcert = CTCert(self._otp)
			self._secinfo = SecureInfo(base64.b64decode(settings['secureinfo'][:0x16C]), self._otp.is_dev)
		except Exception as e:
			raise ClassInitError("Failed loading OTP, CTCert or SecureInfo") from e

		self._msed = settings.get('msed', None)
		if self._msed is None:
			self._msed = MovableSed.generate_from_otp(self._otp)
			self._msed.fixup_footer_data(self._otp)
		else:
			self._msed = MovableSed(base64.b64decode(self._msed[:0x1AC]))

		self._model_override = settings.get('model', None)

		self._region = regionaldata.Region.get_region_str(settings.get('region', self._secinfo.region))
		self._country = regionaldata.Country.get_country_str(settings.get('country', None))
		self._language = regionaldata.Language.get_language_str(settings.get('language', None))

		self._orig_region = self._secinfo.region_str

		self._titles = {
			MediaType.NAND: [],
			MediaType.SD: [],
			MediaType.GAME_CARD: None
		}

		def _try_title(x):
			try:
				return Title(*x)
			except (TypeError, ClassInitError):
				return None

		titles = settings.get('titles', self._titles)
		if isinstance(titles, dict):
			nand_titles = titles.get(MediaType.NAND, [])
			sd_titles = titles.get(MediaType.SD, [])
			cart_title = titles.get(MediaType.GAME_CARD, None)
			nand_titles = nand_titles if isinstance(nand_titles, list) else []
			sd_titles = sd_titles if isinstance(sd_titles, list) else []
			cart_title = cart_title if isinstance(cart_title, list) else None

			tmp_nand = {}
			tmp_sd = {}

			for i in nand_titles:
				title = _try_title(i)
				if title is None:
					continue
				_title = tmp_nand.get(int(title), None)
				title = title if _title is None else max(title, _title)
				tmp_nand[int(title)] = title

			for i in sd_titles:
				title = _try_title(i)
				if title is None:
					continue
				_title = tmp_sd.get(int(title), None)
				title = title if _title is None else max(title, _title)
				tmp_sd[int(title)] = title

			for i, y in tmp_nand.items():
				self._titles[MediaType.NAND] += y

			del tmp_nand

			for i, y in tmp_sd.items():
				self._titles[MediaType.SD] += y

			del tmp_sd

			if cart_title:
				self._titles[MediaType.GAME_CARD] = _try_title(cart_title)

		self._is_doing_init = 1

		self.region_change(self._region, self._country, self._language) # will validate things

		del self._is_doing_init

		self._ecommerce_info = settings.get('ecommerce_info', {})
		if not isinstance(self._ecommerce_info, dict):
			raise ClassInitError("ECommerce information invalid")

	def serialize_json(
		self,
		*,
		json_fp: typing.Optional[typing.TextIO] = None,
		json_file: typing.Optional[str] = None,
		**kwargs
	) -> typing.Optional[str]:
		settings = OrderedDict()
		settings['otp'] = base64.b64encode(bytes(self._otp)).decode()
		settings['secureinfo'] = base64.b64encode(bytes(self._secinfo)).decode()
		settings['msed'] = base64.b64encode(bytes(self._msed)).decode()
		settings['model'] = self._model_override
		settings['region'] = self._region
		if self._country:
			settings['country'] = self._country
		settings['language'] = self._language
		settings['ecommerce_info'] = self._ecommerce_info
		settings['titles'] = OrderedDict()
		settings['titles'][MediaType.NAND] = [i.export_tuple for i in self._titles[MediaType.NAND]]
		settings['titles'][MediaType.SD] = [i.export_tuple for i in self._titles[MediaType.SD]]
		settings['titles'][MediaType.GAME_CARD] = self._titles[MediaType.GAME_CARD].export_tuple if self._titles[MediaType.GAME_CARD] else None
		if json_fp:
			json.dump(settings, json_fp, indent=2)
		elif json_file:
			with open(json_file, 'w', encoding='utf-8') as file:
				json.dump(settings, file, indent=2)
		else:
			return json.dumps(settings, indent=2)

	@staticmethod
	def generate_new_json(
		*,
		otp_data: typing.Union[OTP, typing.SupportsBytes, None] = None, # otp bytes data
		otp_fp: typing.Optional[typing.BinaryIO] = None, # or otp read binary io
		otp_file: typing.Optional[str] = None, # otherwise otp file path
		secureinfo_data: typing.Union[OTP, typing.SupportsBytes, None] = None, # secureinfo bytes data
		secureinfo_fp: typing.Optional[typing.BinaryIO] = None, # or secureinfo read binary io
		secureinfo_file: typing.Optional[str] = None, # otherwise secureinfo file path
		serialnumber: typing.Optional[str] = None, # not used if secureinfo given
		msed_data: typing.Union[MovableSed, typing.SupportsBytes, None] = None, # generated unsigned from OTP if msed not given
		msed_fp: typing.Optional[typing.BinaryIO] = None, # generated unsigned from OTP if msed not given
		msed_file: typing.Optional[str] = None, # generated unsigned from OTP if msed not given
		model_override: typing.Optional[CTRModel_T] = None, # model to override serial number based detection
		region: typing.Optional[regionaldata.RegionType] = None, # optional if secureinfo is given instead of just serial
		country: typing.Optional[regionaldata.CountryType] = None, # optional if region has only one country
		language: typing.Optional[regionaldata.LanguageType] = None, # default language if not given
		json_fp: typing.Optional[typing.TextIO] = None, # any file-like textio writable object valid for json.dump
		json_file: typing.Optional[str] = None, # any path-like object valid for open if json_fp was not given
		**kwargs
	) -> typing.Optional[str]:
		otp = None

		if otp_data:
			otp = OTP(otp_data)
		elif otp_fp:
			otp = OTP(otp_fp.read(0x100))
		elif otp_file:
			with open(otp_file, 'rb') as i:
				otp = OTP(i.read(0x100))

		if not otp:
			raise DataProcessingError("No OTP loaded")

		secureinfo = None

		if secureinfo_data:
			secureinfo = SecureInfo(secureinfo_data, otp.is_dev)
		elif secureinfo_fp:
			secureinfo = SecureInfo(secureinfo_fp.read(0x111), otp.is_dev)
		elif secureinfo_file:
			with open(secureinfo_file, 'rb') as i:
				secureinfo = SecureInfo(i.read(0x111), otp.is_dev)
		elif serialnumber:
			if regionaldata.Region.get_region(region) is None:
				raise DataProcessingError("Region required if using a serial number instead of a SecureInfo")
			secureinfo = SecureInfo.create_from_serial_number(serialnumber, region, otp.is_dev)

		if not secureinfo:
			raise DataProcessingError("No SecureInfo loaded")

		if msed_data:
			msed = MovableSed(msed_data)
		elif msed_fp:
			msed = MovableSed(msed_fp.read(0x140))
		elif msed_file:
			with open(msed_file, 'rb') as i:
				msed = MovableSed(i.read(0x140))
		else:
			msed = MovableSed.generate_from_otp(otp)

		if model_override is not None and model_override.upper() not in ['CTR', 'SPR', 'FTR', 'KTR', 'RED', 'JAN']:
			raise DataProcessingError("Invalid model override")

		model_override = model_override.upper() if model_override is not None else None

		region = regionaldata.Region.get_region(secureinfo.region if region is None else region)
		country = regionaldata.Country.get_country(country)
		language = regionaldata.Language.get_language(language)

		if region is None:
			raise DataProcessingError("No valid region")

		if region == regionaldata.Region.TWN and language is not None and language == regionaldata.Language.ZH:
			language = regionaldata.Language.ZH_TRAD

		if region == regionaldata.Region.AUS:
			raise DataProcessingError("AUS is a region that has an assigned value, but not properly usable")

		valid_countries = regionaldata.Country.get_region_country_list(region)

		if country is not None:
			if country not in valid_countries:
				raise DataProcessingError("Country not valid for region. Applicable ISO 3166-1 Alpha-2 for this region: " + (", ".join([i.name for i in valid_countries])))
		else:
			if len(valid_countries) > 1:
				raise DataProcessingError("No country specified on a region with more than one option, cannot load a default. Applicable ISO 3166-1 Alpha-2 for this region: " + (", ".join([i.name for i in valid_countries])))

			warnings.warn("Country not specified, but only one option available on region, loading default")
			country = valid_countries[0]

		del valid_countries

		if language is not None:
			valid_languages = regionaldata.Language.get_region_language_list(region)

			if language not in valid_languages:
				warnings.warn("Dubious language for region, loading default")
				language = valid_languages[0]

			del valid_languages
		else:
			language = regionaldata.Language.get_region_language_list(region)[0]

		settings = OrderedDict()
		settings['otp'] = base64.b64encode(bytes(otp)).decode()
		settings['secureinfo'] = base64.b64encode(bytes(secureinfo)).decode()
		settings['msed'] = base64.b64encode(bytes(msed)).decode()
		settings['model'] = model_override
		settings['region'] = regionaldata.Region.get_region_str(region)
		settings['country'] = regionaldata.Country.get_country_str(country)
		settings['language'] = regionaldata.Language.get_language_str(language)
		# ecommerce info and titles are not needed to be init here
		# after all, if missing, init loads defaults
		if json_fp:
			json.dump(settings, json_fp, indent=2)
		elif json_file:
			with open(json_file, 'w', encoding='utf-8') as file:
				json.dump(settings, file, indent=2)
		else:
			return json.dumps(settings, indent=2)

	def reboot(self) -> None:
		self._boottime.reboot()

	def sleep_with_rng_curve(
		self,
		sleep_min_time: typing.Union[int, float],
		rng_multiplier: typing.Union[int, float] = 1
	) -> None:
		self._boottime.sleep_with_rng_curve(sleep_min_time, rng_multiplier)

	def ap_sign(self, title_id: typing.SupportsInt, data: typing.SupportsBytes) -> typing.Tuple[bytes, bytes]:
		data = bytes(data)
		apcert = APCert(self._ctcert, title_id)
		signature = apcert.private_key().sign(data, ec.ECDSA(hashes.SHA256()))
		signature = crypto_utils.decode_dss_signature(signature)
		return (bytes(apcert), pack("30s30s", signature[0].to_bytes(30, 'big'), signature[1].to_bytes(30, 'big')))

	def export_ivs(self) -> bytes:
		ivs = self._msed.produce_ivs()
		if ivs is None:
			raise DataProcessingError("Could not export IVS successfully")
		return ivs

	def import_ivs(self, ivs: typing.SupportsBytes) -> None:
		msed = self._msed.load_from_ivs(ivs, self._otp.is_dev)
		if msed is None:
			raise DataProcessingError("Could not import IVS successfully")
		msed.fixup_footer_data(self._otp)
		self._msed = msed

	def region_change(
		self,
		region: regionaldata.RegionType,
		country: typing.Optional[regionaldata.CountryType] = None,
		language: typing.Optional[regionaldata.LanguageType] = None
	) -> None:
		region = regionaldata.Region.get_region(region)
		country = regionaldata.Country.get_country(country)
		language = regionaldata.Language.get_language(language)

		if region is None:
			raise DataProcessingError("No valid region")

		if region == regionaldata.Region.TWN and language is not None and language == regionaldata.Language.ZH:
			language = regionaldata.Language.ZH_TRAD

		if region == regionaldata.Region.AUS:
			raise DataProcessingError("AUS is a region that has an assigned value, but not properly usable")

		valid_countries = regionaldata.Country.get_region_country_list(region)

		if country is not None:
			if country not in valid_countries:
				raise DataProcessingError("Country not valid for region. Applicable ISO 3166-1 Alpha-2 for this region: " + (", ".join([i.name for i in valid_countries])))
		else:
			if len(valid_countries) > 1:
				raise DataProcessingError("No country specified on a region with more than one option, cannot load a default. Applicable ISO 3166-1 Alpha-2 for this region: " + (", ".join([i.name for i in valid_countries])))

			warnings.warn("Country not specified, but only one option available on region, loading default")
			country = valid_countries[0]

		del valid_countries

		if language is not None:
			valid_languages = regionaldata.Language.get_region_language_list(region)

			if language not in valid_languages:
				warnings.warn("Dubious language for region, loading default")
				language = valid_languages[0]

			del valid_languages
		else:
			language = regionaldata.Language.get_region_language_list(region)[0]

		curr_region = regionaldata.Region.get_region(self._region)

		sys_titles_curr = (n3ds_sys_titles if self.is_n3ds else o3ds_sys_titles)[curr_region]
		sys_titles_new = (n3ds_sys_titles if self.is_n3ds else o3ds_sys_titles)[region]
		sys_titles_curr = sys_titles_curr if sys_titles_curr else []
		sys_titles_new = sys_titles_new if sys_titles_new else []
		if hasattr(self, '_is_doing_init'):
			nand_titles = [i for i in self._titles[MediaType.NAND] if (not Title.is_ctranysys(int(i)) or int(i) in sys_titles_curr)]
			nand_titles += [i for i in sys_titles_curr if int(i) not in nand_titles]
		else:
			nand_titles = list(sys_titles_new).copy() if sys_titles_new else []
			nand_titles += [i for i in self._titles[MediaType.NAND] if not Title.is_ctranysys(int(i))]
		self._titles[MediaType.NAND] = nand_titles

		self._region = regionaldata.Region.get_region_str(region)
		self._country = regionaldata.Country.get_country_str(country)
		self._language = regionaldata.Language.get_language_str(language)

	def country_change(self, country: typing.Optional[regionaldata.CountryType]) -> None:
		region = regionaldata.Region.get_region(self._region)
		country = regionaldata.Country.get_country(country)

		valid_countries = regionaldata.Country.get_region_country_list(region)

		if country is not None:
			if country not in valid_countries:
				raise DataProcessingError("Country not valid for region. Applicable ISO 3166-1 Alpha-2 for this region: " + (", ".join([i.name for i in valid_countries])))
		else:
			if len(valid_countries) > 1:
				raise DataProcessingError("No country specified on a region with more than one option, cannot load a default. Applicable ISO 3166-1 Alpha-2 for this region: " + (", ".join([i.name for i in valid_countries])))

			warnings.warn("Country not specified, but only one option available on region, loading default")
			country = valid_countries[0]

		del valid_countries

		self._country = regionaldata.Country.get_country_str(country)

	def language_change(self, language: typing.Optional[regionaldata.LanguageType]) -> None:
		region = regionaldata.Region.get_region(self._region)
		language = regionaldata.Language.get_language(language)

		if region == regionaldata.Region.TWN and language is not None and language == regionaldata.Language.ZH:
			language = regionaldata.Language.ZH_TRAD

		if language is not None:
			valid_languages = regionaldata.Language.get_region_language_list(region)

			if language not in valid_languages:
				warnings.warn("Dubious language for region, loading default")
				language = valid_languages[0]

			del valid_languages
		else:
			language = regionaldata.Language.get_region_language_list(region)[0]

		self._language = regionaldata.Language.get_language_str(language)

	def update_ecommerce(self, info: dict) -> None:
		if not isinstance(info, dict):
			raise DataProcessingError("ECommerce information invalid")

		self._ecommerce_info = info.copy()

	def drop_ecommerce(self) -> None:
		self._ecommerce_info = {}

	def titles(self, media: MediaType) -> typing.Iterable[Title]:
		media = MediaType(media)
		if media == MediaType.GAME_CARD:
			return [self._titles[media]] if self._titles[media] else []
		return list(self._titles[media]).copy()

	@property
	def ct_cert(self) -> bytes:
		return bytes(self._ctcert)

	@property
	def ct_cert_full(self) -> CTCert:
		return self._ctcert

	@property
	def msed(self) -> MovableSed:
		return self._msed

	@property
	def boot_time_ms(self) -> int:
		return self._boottime.get_microseconds

	@property
	def ecommerce_info(self) -> dict:
		return self._ecommerce_info.copy()

	@property
	def device_id(self) -> int:
		return self._otp.device_id

	@property
	def serial_no(self) -> str:
		return self._secinfo.serial

	@property
	def model_override(self) -> typing.Optional[CTRModel_T]:
		return self._model_override

	@property
	def original_region(self) -> str:
		"""As per secureinfo"""
		return self._orig_region

	@property
	def region(self) -> str:
		return self._region

	@property
	def country(self) -> str:
		return self._country

	@property
	def language(self) -> str:
		return self._language

	@property
	def is_n3ds(self) -> bool:
		return (self.device_id & 0x80000000) != 0 

	@property
	def is_dev(self) -> bool:
		return self._otp.is_dev

	@property
	def is_retail(self) -> bool:
		return not self._otp.is_dev

	@property
	def has_ecommerce_info(self) -> bool:
		return self._ecommerce_info.get('account_status', None) is not None

	@property
	def time_padding_emu(self):
		return self._time_padding_emu
