from enum import IntEnum, unique
import typing

from . import regionaldata
from ..exception import ClassInitError

__all__ = [
	"MediaType",
	"Title"
]

@unique
class MediaType(IntEnum):
	NAND = 0
	SD = 1
	GAME_CARD = 2

class Title:
	def __init__(
		self,
		tid: typing.SupportsInt,
		version: typing.SupportsInt,
		region: typing.Optional[regionaldata.RegionType] = None, # None for all
		downloadable: bool = True
	):
		self._tid = int(tid) & 0xFFFFFFFFFFFFFFFF
		self._version = int(version) & 0xFFFF
		self._version_chunks = (
			self._version >> 10,
			(self._version >> 4) & 0x3F,
			self._version & 0xF
		)
		self._region = regionaldata.Region.get_region(region)
		if self._region is None and region is not None:
			raise ClassInitError("Invalid title region")
		self._downloadable = bool(downloadable)

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		if self._region is None:
			return f"<{modname}.{clsname} id=0x{self._tid:016x} version={self._version} version_chunks={self._version_chunks}>"
		return f"<{modname}.{clsname} id=0x{self._tid:016x} version={self._version} version_chunks={self._version_chunks} region={repr(self._region)}>"

	def __int__(self):
		return self._tid

	def __eq__(self, rhs):
		if isinstance(rhs, int):
			return self._tid == rhs
		if isinstance(rhs, Title):
			return self._tid == rhs._tid and self._version == rhs._version
		return NotImplemented

	def __ne__(self, rhs):
		if isinstance(rhs, int):
			return self._tid != rhs
		if isinstance(rhs, Title):
			return self._tid != rhs._tid or self._version != rhs._version
		return NotImplemented

	def __lt__(self, rhs):
		if isinstance(rhs, int):
			return self._tid < rhs # or (self._tid == rhs and self._version < 0)
		if isinstance(rhs, Title):
			return self._tid < rhs._tid or (self._tid == rhs._tid and self._version < rhs._version)
		return NotImplemented

	def __le__(self, rhs):
		if isinstance(rhs, int):
			return self._tid < rhs or (self._tid == rhs and self._version <= 0)
		if isinstance(rhs, Title):
			return self._tid < rhs._tid or (self._tid == rhs._tid and self._version <= rhs._version)
		return NotImplemented

	def __gt__(self, rhs):
		if isinstance(rhs, int):
			return self._tid > rhs or (self._tid == rhs and self._version > 0)
		if isinstance(rhs, Title):
			return self._tid > rhs._tid or (self._tid == rhs._tid and self._version > rhs._version)
		return NotImplemented

	def __ge__(self, rhs):
		if isinstance(rhs, int):
			return self._tid > rhs or (self._tid == rhs and self._version >= 0)
		if isinstance(rhs, Title):
			return self._tid > rhs._tid or (self._tid == rhs._tid and self._version >= rhs._version)
		return NotImplemented

	@property
	def id(self) -> int:
		return self._tid

	@property
	def version(self) -> int:
		return self._version

	@property
	def version_major(self) -> int:
		return self._version_chunks[0]

	@property
	def version_minor(self) -> int:
		return self._version_chunks[1]

	@property
	def version_revision(self) -> int:
		return self._version_chunks[2]

	@property
	def version_chunks(self) -> typing.Tuple[int, int, int]:
		return self._version_chunks

	@property
	def region(self) -> typing.Optional[regionaldata.Region]:
		return self._region

	@property
	def downloadable(self) -> bool:
		return self._downloadable

	@property
	def export_tuple(self) -> typing.Tuple[int, int, typing.Optional[int], bool]:
		return (self._tid, self._version, int(self._region) if self._region else None, self._downloadable)

	@staticmethod
	def is_ctr(tid: typing.SupportsInt) -> bool:
		return (int(tid) & 0xFFFF400000000000) == 0x0004000000000000

	@staticmethod
	def is_ctrtwl(tid: typing.SupportsInt) -> bool:
		return (int(tid) & 0xFFFFC00000000000) == 0x0004800000000000

	@staticmethod
	def is_ctrsys(tid: typing.SupportsInt) -> bool:
		return (int(tid) & 0xFFFFC01000000000) == 0x0004001000000000

	@staticmethod
	def is_ctrtwlsys(tid: typing.SupportsInt) -> bool:
		return (int(tid) & 0xFFFFC00100000000) == 0x0004800100000000

	@classmethod
	def is_ctranysys(cls, tid: typing.SupportsInt) -> bool:
		return cls.is_ctrsys(tid) or cls.is_ctrtwlsys(tid)

	@staticmethod
	def is_ctrdlc(tid: typing.SupportsInt) -> bool:
		return (int(tid) & 0xFFFFFFFF00000000) == 0x0004008C00000000

	@staticmethod
	def is_ctrdlp(tid: typing.SupportsInt) -> bool:
		return (int(tid) & 0xFFFFFFFF00000000) == 0x0004000100000000

	@staticmethod
	def is_ctrdemo(tid: typing.SupportsInt) -> bool:
		return (int(tid) & 0xFFFFFFFF00000000) == 0x0004000200000000

	@staticmethod
	def is_ctrlicence(tid: typing.SupportsInt) -> bool:
		return (int(tid) & 0xFFFFFFFF00000000) == 0x0004000D00000000

	@staticmethod
	def is_ctrupdate(tid: typing.SupportsInt) -> bool:
		return (int(tid) & 0xFFFFFFFF00000000) == 0x0004000E00000000
