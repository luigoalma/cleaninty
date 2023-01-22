import pycurl, typing, re
from collections import OrderedDict

from .exception import CleanintyExceptionBase, ClassInitError

__all__ = [
	"Connection",
	"SimpleDownloadBuffer",
	"MultiWriter",
	"WriterFuncType",
	"ParameterSetError"
]

WriterFuncType = typing.Callable[
	[typing.SupportsBytes], None
]

class ParameterSetError(CleanintyExceptionBase):
	"""General Connection parameter setting exception"""

class SimpleDownloadBuffer:
	def __init__(self):
		self._data = b''
		self._data_chunks = []

	def write(self, x: typing.SupportsBytes) -> None:
		self._data_chunks.append(bytes(x))

	def get(self) -> bytes:
		if self._data_chunks:
			self._data += b''.join(self._data_chunks)
			self._data_chunks.clear()
		return self._data

class MultiWriter:
	def __init__(self, writers: typing.Iterable[WriterFuncType]):
		self._writers = []
		for i in writers:
			if not callable(i):
				raise ClassInitError("non callable on a callable list!")
			self._writers.append(i)
		self._writers = tuple(self._writers)

	def write(self, x: typing.SupportsBytes) -> None:
		for i in self._writers:
			i(x)

class Connection:
	def __init__(self, *, max_connects: int = 1):
		self._headers = []
		self._keepalive = False
		try:
			self._curl_handle = pycurl.Curl()
			self._curl_handle.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
			self._curl_handle.setopt(pycurl.MAXCONNECTS, max_connects)
			self._curl_handle.setopt(pycurl.TCP_KEEPALIVE, 0)
		except Exception as e:
			raise ClassInitError("Failed to initialize curl handle") from e

	def __del__(self):
		self.close()

	def _validate_header(self, name, value):
		if not isinstance(name, str) or \
			not re.fullmatch("^[A-Za-z0-9!#$%&'*+-.^_`|~]+$", name):
			return False
		if value is not None and \
			(not isinstance(value, str) or \
				(value and not re.fullmatch("^[\\x09\\x20-\\x7e]+$", value))
			):
			return False
		return True

	def _get_header_list(self):
		headers = []
		default_overrides = OrderedDict()
		default_overrides['user-agent'] = 'User-Agent:'
		default_overrides['accept'] = 'Accept:'

		for v in self._headers:
			if isinstance(v[1], str) and len(v[1]) != 0:
				header = v[0] + ': ' + v[1]
			elif v[1] is None:
				header = v[0] + ':'
			else:
				header = v[0] + ';'
			headers.append(header)
			default_overrides.pop(v[0].lower(), None)

		headers = list(default_overrides.values()) + headers

		return headers

	def set_keepalive(
		self,
		keepalive: bool,
		keepidle: typing.SupportsInt = 120,
		keepintvl: typing.SupportsInt = 60
	) -> None:
		try:
			if keepalive:
				keepidle = int(keepidle)
				keepintvl = int(keepintvl)

				if keepidle < 0 and keepintvl < 0:
					raise ParameterSetError("keepidle or keepintvl can't be negative")

				self._curl_handle.setopt(pycurl.TCP_KEEPIDLE, keepidle)
				self._curl_handle.setopt(pycurl.TCP_KEEPINTVL, keepintvl)
				self._curl_handle.setopt(pycurl.TCP_KEEPALIVE, 1)
				self._keepalive = True

			else:
				self._curl_handle.setopt(pycurl.TCP_KEEPALIVE, 0)
				self._keepalive = False

		except Exception as e:
			raise ParameterSetError("Failed to set keep-alive option") from e

	def set_header(self, name: str, value: typing.Optional[str]) -> None:
		if not self._validate_header(name, value):
			raise ParameterSetError("Could not validate field name or value")

		if value is None:
			self.remove_header(name, all_elements = True)
			return

		self._headers.append([name, value])

	def reset_headers(self):
		self._headers.clear()

	def remove_header(
		self,
		name: str,
		*,
		latest_element: bool = True,
		all_elements: bool = False
	) -> typing.Optional[typing.List[str]]:
		if not self._validate_header(name, None):
			raise ParameterSetError("Could not validate field name")

		_name = name.lower()

		_headers = self._headers.copy()
		if latest_element or all_elements:
			_headers.reverse()

		if all_elements:
			for i, j in enumerate(_headers):
				if j[0].lower() == _name:
					self._headers.pop((len(_headers) - i - 1))
			return None

		index = -1
		for i, j in enumerate(_headers):
			if j[0].lower() != _name:
				continue

			index = (len(_headers) - i - 1) if latest_element else i
			break

		return self._headers.pop(index) if index >= 0 else None

	def set_cainfo(self, path: typing.Optional[str]) -> None:
		try:
			self._curl_handle.setopt(pycurl.CAINFO, path)
		except Exception as e:
			raise ParameterSetError("Failed setting CAINFO") from e

	def set_cli_cert(self, cert_path: typing.Optional[str], key_path: typing.Optional[str]) -> None:
		try:
			self._curl_handle.setopt(pycurl.SSLCERT, cert_path)
			self._curl_handle.setopt(pycurl.SSLKEY, key_path)
		except Exception as e:
			raise ParameterSetError("Failed setting client certificate") from e

	def set_url(self, url: str) -> None:
		try:
			self._curl_handle.setopt(pycurl.URL, str(url))
		except Exception as e:
			raise ParameterSetError("Failed setting url") from e

	def set_customrequest(self, request: typing.Optional[str] = None):
		try:
			self._curl_handle.setopt(pycurl.CUSTOMREQUEST, str(request))
		except Exception as e:
			raise ParameterSetError("Failed setting custom request") from e

	def set_verbose(self, toggle: bool) -> None:
		try:
			self._curl_handle.setopt(pycurl.VERBOSE, 1 if toggle else 0)
		except Exception as e:
			raise ParameterSetError("Failed setting verbose") from e

	def set_post_data(self, data: typing.Union[str, bytes, None]) -> None:
		try:
			if data:
				self._curl_handle.setopt(pycurl.POSTFIELDSIZE, len(data))
				self._curl_handle.setopt(pycurl.POSTFIELDS, data)
				self._data = data
			else:
				self._curl_handle.setopt(pycurl.POST, 0)
				self._data = None
		except Exception as e:
			raise ParameterSetError("Failed setting post data") from e

	def set_write_function(self, func: typing.Optional[WriterFuncType]) -> None:
		try:
			self._curl_handle.setopt(pycurl.WRITEFUNCTION, func)
		except Exception as e:
			raise ParameterSetError("Failed setting write function") from e

	def set_write_header_function(self, func: typing.Optional[WriterFuncType]) -> None:
		try:
			self._curl_handle.setopt(pycurl.HEADERFUNCTION, func)
		except Exception as e:
			raise ParameterSetError("Failed setting write function") from e

	def set_nobody(self, toggle: bool) -> None:
		try:
			self._curl_handle.setopt(pycurl.NOBODY, 1 if toggle else 0)
		except Exception as e:
			raise ParameterSetError("Failed setting nobody") from e

	def perform(self) -> int:
		headers = self._get_header_list()
		try:
			self._curl_handle.setopt(pycurl.HTTPHEADER, headers)
		except Exception as e:
			raise ParameterSetError("Failed setting headers") from e

		self._curl_handle.perform()

		return self._curl_handle.getinfo(pycurl.RESPONSE_CODE)

	def close(self) -> None:
		self._curl_handle.close()

	@property
	def is_keepalive(self) -> bool:
		return self._keepalive
