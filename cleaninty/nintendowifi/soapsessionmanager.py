import typing, abc
from ..connection import Connection

class SoapSessionManager(metaclass=abc.ABCMeta):
	@abc.abstractmethod
	def sleep_with_rng_curve(
		self,
		sleep_min_time: typing.Union[int, float],
		rng_multiplier: typing.Union[int, float] = 1
	) -> None:
		"""
		For time padding emulation assistance.
		"""

	@abc.abstractmethod
	def get_connection(self) -> Connection:
		"""
		Return either a new or existing managed connection object.
		"""

	@abc.abstractmethod
	def set_service_standby(self, status: bool) -> None:
		"""
		Set service standby status from SOAP envelope response.
		"""

	@property
	@abc.abstractmethod
	def is_time_emu_enabled(self) -> bool:
		"""
		Either to do padding of time or not.
		"""

	@property
	@abc.abstractmethod
	def service_standby(self) -> bool:
		"""
		Indicate if service is in standby.
		"""

	@property
	@abc.abstractmethod
	def device_id(self) -> int:
		"""
		Device's uint32 device id.
		"""

	@property
	@abc.abstractmethod
	def message_id_step(self) -> int:
		"""
		Last chunk for <MessageId>, initially should be unique to the last SOAP sent.
		E.g. 3DS uses current boot time in ticks converted to microseconds.
		"""

	@property
	@abc.abstractmethod
	def has_tokens(self) -> bool:
		"""
		Indication of ST/WT tokens being available.
		"""

	@property
	@abc.abstractmethod
	def st_token(self) -> typing.Optional[str]:
		"""
		Returns the ST token given by Identification SOAP server.
		This token is more critical to identify the device.
		"""

	@property
	@abc.abstractmethod
	def wt_token(self) -> typing.Optional[str]:
		"""
		Returns the WT token hashed from ST token.
		It's lower caps hexadecimal string of the MD5 digest of the ST token.
		"""

	@property
	@abc.abstractmethod
	def account_id(self) -> typing.Optional[int]:
		"""
		Account id retrieved from Identification SOAP server.
		"""

	@property
	@abc.abstractmethod
	def account_status(self) -> typing.Optional[str]:
		"""
		Account status indicator.
		"""

	@property
	@abc.abstractmethod
	def application_id(self) -> typing.Optional[int]:
		"""
		uint64 application title id that is requesting the service to do SOAPs.
		"""

	@property
	@abc.abstractmethod
	def tin(self) -> typing.Optional[int]:
		"""
		Application's TIN.
		"""

	@property
	@abc.abstractmethod
	def age(self) -> typing.Optional[int]:
		"""
		Some positive number no bigger than 255.
		Still not sure of what's its effect.
		Session only value, not stored.
		"""

	@property
	@abc.abstractmethod
	def region(self) -> typing.Optional[str]:
		"""
		Region short string.
		"""

	@property
	@abc.abstractmethod
	def country(self) -> typing.Optional[str]:
		"""
		Country short string.
		"""

	@property
	@abc.abstractmethod
	def language(self) -> typing.Optional[str]:
		"""
		Language short string.
		"""

	@property
	@abc.abstractmethod
	def serial_no(self) -> str:
		"""
		Console's serial number string.
		"""

	@property
	@abc.abstractmethod
	def user_agent(self) -> str:
		"""
		User-agent string used for http(s) communications.
		"""

	@property
	@abc.abstractmethod
	def keepalive(self) -> bool:
		"""
		Specify specifically connection header keep-alive or close.
		"""

	@property
	@abc.abstractmethod
	def ssl_cert_path(self) -> typing.Optional[str]:
		"""
		SSL certificates used to verify https.
		"""

	@property
	@abc.abstractmethod
	def ssl_cli_cert_paths(self) -> typing.Optional[typing.Tuple[str, ...]]:
		"""
		SSL client certificates for client authentification.
		"""
