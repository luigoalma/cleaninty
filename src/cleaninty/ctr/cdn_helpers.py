from struct import pack
import typing, os, pathlib

from .cdn import CDN, CDNDownloadStage, AssistedCDNDownload
from .tmd import ContentChunkRecord, ContentTypeFlags
from .exception import CTRExceptionBase, ClassInitError, DataProcessingError
from ..connection import WriterFuncType, MultiWriter

__all__ = [
	"CiaCDNBuilder",
	"CDNFolderDownload",
	"CDNMultiHelper"
]

def _exception_try_shield(inform_except: str, except_ret: typing.Any = None):
	def inner(func):
		def wrapper(self, *args, **kwargs):
			try:
				return func(self, *args, **kwargs)
			except Exception:
				getattr(self, inform_except)()
				return except_ret
		return wrapper
	return inner

class CiaCDNBuilder:
	def __init__(self, output: str, rollback_optional_failed_content: bool = False):
		self._path = pathlib.Path(output).resolve()
		self._outfile = self._path.open("wb")
		self._errorstate = False
		self._end_flag = False
		self._has_ended = False

		self._cert_chain_size = 0
		self._tik_size = 0
		self._tmd_size = 0
		self._content_off = -1

		self._curr_content_off = -1
		self._limit_write = -1
		self._curr_optional = False
		self._rollback_opt_content = bool(rollback_optional_failed_content)

		self._index_field = 0

		self._last_stage = -1

		self._ensure_seek(0x2040)

	def __del__(self):
		self._end()

	def _block_align_up(self) -> None:
		self._ensure_seek(self._calc_align_up(self._outfile.tell()))

	def _calc_align_up(self, x: int) -> int:
		return ((x + 0x3F) >> 6) << 6

	def _error(self) -> None:
		if self._errorstate:
			return

		if self._rollback_opt_content and \
			self._last_stage == CDNDownloadStage.CONTENT and \
			self._curr_content_off != -1 and \
			self._curr_optional:
			try:
				self._rollback_opt_content = False # safe guard against failed rollbacks
				self._ensure_seek(self._curr_content_off)
				size = self._outfile.truncate()
				if size != self._curr_content_off:
					raise Exception("") # escape
				self._curr_content_off = -1
				self._limit_write = -1
				self._curr_optional = False
				self._rollback_opt_content = True
				return
			except Exception:
				pass

		self._errorstate = True
		try:
			self._outfile.close()
		except Exception:
			pass

		try:
			self._path.unlink()
		except Exception:
			pass

	@_exception_try_shield('_error')
	def _end(self) -> None:
		if self._has_ended:
			return

		if not self._end_flag or \
			not self._tmd_size or \
			self._content_off < 0 or \
			self._curr_content_off >= 0:
			self._error()

		while not self._errorstate:
			end_off = self._outfile.tell()
			aligned_end_off = self._calc_align_up(end_off)
			
			if not self._ensure_seek(aligned_end_off) or \
				self._outfile.truncate() != aligned_end_off:
				self._error()
				break

			self._outfile.seek(0)
			if self._outfile.tell() != 0:
				self._error()
				break

			indexes = int.to_bytes(self._index_field, 0x2000, 'big')

			written = self._outfile.write(
				pack(
					"<I HH IIII Q 8192s",
					0x2020,
					0, 0,
					self._cert_chain_size,
					self._tik_size,
					self._tmd_size,
					0,
					end_off - self._content_off,
					indexes
				)
			)

			if written != 0x2020:
				self._error()

			self._outfile.close()

			break

		self._has_ended = True

	@_exception_try_shield('_error')
	def _controlled_write(self, x: typing.SupportsBytes) -> None:
		if self._errorstate:
			return

		x = bytes(x)

		if self._limit_write >= 0:
			self._limit_write -= len(x)
			if self._limit_write < 0:
				self._error()
				return

		l = self._outfile.write(x)

		if l != len(x):
			self._error()

	@_exception_try_shield('_error', False)
	def _ensure_seek(self, offset: int) -> bool:
		if self._errorstate:
			return False

		self._outfile.seek(offset)

		if self._outfile.tell() != offset:
			self._error()
			return False

		return True

	@_exception_try_shield('_error')
	def _tmd_end(self, cdn: CDN) -> None:
		off = self._outfile.tell()
		for i, j in cdn.certs.items():
			self._controlled_write(j)

		self._cert_chain_size = self._outfile.tell() - off

		self._block_align_up()

		tik = cdn.ticket
		if tik is not None:
			self._tik_size = len(tik)
			self._controlled_write(tik.installable_export)

			self._block_align_up()

		tmd = cdn.tmd
		if tmd is None:
			self._error()
			return

		self._tmd_size = len(tmd)
		self._controlled_write(tmd)

		self._block_align_up()

		self._content_off = self._outfile.tell()

	@_exception_try_shield('_error')
	def _content_start(self, chunk: ContentChunkRecord) -> typing.Optional[WriterFuncType]:
		if self._curr_content_off >= 0:
			self._error()
			return

		self._limit_write = chunk.size

		self._curr_content_off = self._outfile.tell()

		self._curr_optional = bool(chunk.type & ContentTypeFlags.Optional)

		return self._controlled_write

	@_exception_try_shield('_error')
	def _content_end(self, chunk: ContentChunkRecord) -> None:
		if self._curr_content_off < 0:
			return

		if self._limit_write > 0:
			self._error()
			return

		size = self._outfile.tell() - self._curr_content_off

		if size != chunk.size:
			self._error()
			return

		self._index_field |= 1 << (0xFFFF - chunk.index)

		self._curr_content_off = -1
		self._limit_write = -1
		self._curr_optional = False

		self._block_align_up()

	@_exception_try_shield('_error')
	def notify(
		self,
		stage: CDNDownloadStage,
		chunk: ContentChunkRecord,
		starting: bool,
		http_ret: int,
		cdn: CDN
	) -> typing.Optional[WriterFuncType]:
		if self._end_flag or self._errorstate:
			return None

		if self._last_stage > stage:
			self._error()
			return None

		if self._rollback_opt_content and \
			http_ret == 404 and \
			stage == CDNDownloadStage.CONTENT:
			return None

		if http_ret != 200 and http_ret != 0:
			self._error()
			return None

		self._last_stage = stage

		if stage == CDNDownloadStage.TMD and not starting:
			return self._tmd_end(cdn)

		if stage == CDNDownloadStage.CONTENT and starting:
			return self._content_start(chunk)

		if stage == CDNDownloadStage.CONTENT and not starting:
			return self._content_end(chunk)

		if stage == CDNDownloadStage.END:
			self._end_flag = True
			self._end()

	@_exception_try_shield('_error', True)
	def in_error(self) -> bool:
		return self._errorstate

	def abort(self) -> None:
		self._error()

AssistedCDNDownload.register(CiaCDNBuilder)

class CDNFolderDownload:
	def __init__(self, output: str):
		self._path = pathlib.Path(output).resolve()
		self._path.mkdir(parents=True, exist_ok=True)
		self._errorstate = False
		self._end_flag = False
		self._has_ended = False

		self._limit_write = -1

		self._last_stage = -1

		self._curr_file = None
		self._curr_path = None
		self._is_open = False

	def __del__(self):
		self._end()

	def _error(self) -> None:
		if self._errorstate:
			return

		self._errorstate = True
		if self._is_open:
			try:
				self._curr_file.close()
				self._is_open = False
			except Exception:
				pass
			try:
				self._curr_path.unlink()
			except Exception:
				pass

	@_exception_try_shield('_error')
	def _end(self):
		if self._has_ended:
			return

		if self._is_open:
			self._close_current()

		self._has_ended = True

	@_exception_try_shield('_error')
	def _controlled_write(self, x: typing.SupportsBytes) -> None:
		if self._errorstate:
			return

		x = bytes(x)

		if self._limit_write >= 0:
			self._limit_write -= len(x)
			if self._limit_write < 0:
				self._error()
				return

		l = self._curr_file.write(x)

		if l != len(x):
			self._error()

	@_exception_try_shield('_error')
	def _close_current(self) -> None:
		if self._limit_write > 0:
			self._error()
			return

		if self._is_open:
			self._curr_file.close()

		self._is_open = False

	@_exception_try_shield('_error')
	def _open_current(self, name: str, limit: int = -1) -> typing.Optional[WriterFuncType]:
		if self._is_open:
			self._error()
			return

		self._curr_path = (self._path / name).resolve()
		self._curr_file = self._curr_path.open("wb")
		self._limit_write = limit
		self._is_open = True

		return self._controlled_write

	@_exception_try_shield('_error')
	def notify(
		self,
		stage: CDNDownloadStage,
		chunk: ContentChunkRecord,
		starting: bool,
		http_ret: int,
		cdn: CDN
	) -> typing.Optional[WriterFuncType]:
		if self._end_flag or self._errorstate:
			return None

		if (http_ret != 404 and http_ret != 200 and http_ret != 0) or \
			self._last_stage > stage:
			self._error()
			return

		self._last_stage = stage

		if not starting and http_ret == 404:
			self._close_current()
			self._curr_path.unlink()

		if not starting and stage != CDNDownloadStage.TMD:
			return self._close_current()

		if stage == CDNDownloadStage.CETK:
			return self._open_current("cetk")

		if stage == CDNDownloadStage.TMD and starting:
			return self._open_current("tmd")

		if stage == CDNDownloadStage.TMD and not starting:
			self._close_current()
			w = self._open_current(f"tmd.{cdn.tmd.title_version}")
			if not w:
				self._error()
				return

			w(cdn.tmd_raw)
			return self._close_current()

		if stage == CDNDownloadStage.CONTENT:
			return self._open_current(f"{chunk.id:08X}")

		if stage == CDNDownloadStage.END:
			self._end_flag = True
			self._end()

	@_exception_try_shield('_error', True)
	def in_error(self) -> bool:
		return self._errorstate

	def abort(self) -> None:
		self._error()

AssistedCDNDownload.register(CDNFolderDownload)

class CDNMultiHelper:
	def __init__(
		self,
		helpers: typing.Iterable[AssistedCDNDownload]
	):
		self._helpers = []
		for i in helpers:
			if not isinstance(i, AssistedCDNDownload):
				raise ClassInitError("Non helper in list")
			self._helpers.append(i)

		self._errorstate = False

	def _error(self):
		self._errorstate = True

	@_exception_try_shield('_error')
	def notify(
		self,
		stage: CDNDownloadStage,
		chunk: ContentChunkRecord,
		starting: bool,
		http_ret: int,
		cdn: CDN
	) -> typing.Optional[WriterFuncType]:
		if self._errorstate:
			return

		writers = []

		for i in self._helpers:
			try:
				w = i.notify(stage, chunk, starting, http_ret, cdn)
				if w is not None and callable(w):
					writers.append(w)
			except Exception as e:
				pass

		return MultiWriter(writers).write if writers else None

	@_exception_try_shield('_error', True)
	def in_error(self) -> bool:
		if self._errorstate:
			return True

		for i in self._helpers:
			if not i.in_error():
				return False

		return True # only if all objects are in error state

	def abort(self) -> None:
		for i in self._helpers:
			try:
				i.abort()
			except Exception:
				pass

		self._errorstate = True

AssistedCDNDownload.register(CDNMultiHelper)
