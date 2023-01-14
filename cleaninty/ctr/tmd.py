from enum import IntEnum, unique
from struct import unpack
import typing, hashlib

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import digitalsignature as digsign
from .exception import CTRExceptionBase, ClassInitError, DataProcessingError

__all__ = [
	"TMD",
	"TitleMetaData",
	"ContentTypeFlags",
	"ContentInfoRecord",
	"ContentChunkRecord"
]

@unique
class ContentTypeFlags(IntEnum):
	Encrypted = 0x1
	Disc = 0x2
	CFM = 0x4
	Optional = 0x4000
	Shared = 0x8000

class ContentInfoRecord:
	def __init__(self, data: typing.SupportsBytes):
		data = bytes(data)[:0x24]

		if len(data) < 0x24:
			raise ClassInitError("Content Info Record does not have sufficient data!")

		segments = unpack(">HH32s", data)

		self._content_index_offset = segments[0]
		self._content_count = segments[1]
		self._content_chunks_sha256 = segments[2]

		self._block = data

	def __bytes__(self):
		return self._block

	def __len__(self):
		return len(self._block)

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} index_offset={self.index_offset} count={self.count} sha256={self.sha256.hex()}>"

	@property
	def index_offset(self) -> int:
		return self._content_index_offset

	@property
	def count(self) -> int:
		return self._content_count

	@property
	def sha256(self) -> bytes:
		return self._content_chunks_sha256

class ContentChunkRecord:
	def __init__(self, data: typing.SupportsBytes):
		data = bytes(data)[:0x30]

		if len(data) < 0x30:
			raise ClassInitError("Content Chunk Record does not have sufficient data!")

		segments = unpack(">IHHQ32s", data)

		self._content_id = segments[0]
		self._content_index = segments[1]
		self._content_type = segments[2]
		self._content_size = segments[3]
		self._content_sha256 = segments[4]

		self._block = data

	def __bytes__(self):
		return self._block

	def __len__(self):
		return len(self._block)

	def __repr__(self):
		modname = self.__class__.__module__
		clsname = self.__class__.__qualname__
		return f"<{modname}.{clsname} id={self.id} index={self.index} type={self.type} size={self.size} sha256={self.sha256.hex()}>"

	@property
	def iv(self) -> bytes:
		return int.to_bytes(self._content_index, 'big').ljust(16, b'\x00')

	@property
	def id(self) -> int:
		return self._content_id

	@property
	def index(self) -> int:
		return self._content_index

	@property
	def type(self) -> int:
		return self._content_type

	@property
	def size(self) -> int:
		return self._content_size

	@property
	def sha256(self) -> bytes:
		return self._content_sha256

class TMD(digsign.IssuedObject):
	def __init__(self, data: typing.SupportsBytes):
		data = bytes(data)

		self._sign = digsign.DigitalSignature(data)

		data = data[len(self._sign):]

		if len(data) < 0x9C4: # 0x9C4 is TMD block size without content chunk records
			raise ClassInitError("Not enough data for TMD")

		segments = unpack(">64s BBB 1s QQ I H 8s 4s B 49s I HHH 2x 32s", data[:0xC4])

		self._issuer_str = segments[0].decode('ascii','replace').split('\x00', 1)[0]
		self._version = segments[1]
		self._ca_crl_version = segments[2]
		self._signed_crl_version = segments[3]
		self._reserved1 = segments[4]
		self._system_version = segments[5]
		self._title_id = segments[6]
		self._title_type = segments[7]
		self._group_id = segments[8]
		self._save_data_size, self._srl_private_save_data_size = unpack("<II", segments[9])
		self._reserved2 = segments[10]
		self._srl_flag = segments[11]
		self._reserved3 = segments[12]
		self._access_rights = segments[13]
		self._title_version = segments[14]
		self._content_count = segments[15]
		self._boot_content = segments[16]
		self._sha256_content_info_records = segments[17]

		if not len(self._issuer_str):
			raise ClassInitError("No TMD issuer")

		if self._issuer_str.find('\uFFFD') != -1:
			raise ClassInitError("Invalid TMD issuer")

		if self._version != 1:
			raise ClassInitError("Unexpected TMD version")

		if not self._content_count:
			raise ClassInitError("No TMD contents")

		if len(data) < 0x9C4 + 0x30 * self._content_count:
			raise ClassInitError("Not enough data for TMD")

		if hashlib.sha256(data[0xC4:0x9C4]).digest() != self._sha256_content_info_records:
			raise ClassInitError("Invalid SHA256 for content infos")

		self._tmd_block = data[:0x9C4 + 0x30 * self._content_count]

		self._content_info_records = tuple([
			ContentInfoRecord(data[i:i+0x24]) for i in range(0xC4, 0x9C4, 0x24)
		])

		effective_info_records = [i for i in self._content_info_records if i.count]
		if sum([i.count for i in effective_info_records]) != self._content_count:
			raise ClassInitError("Content info records don't validate same amount of content chunk records")

		index_list = [i.index_offset for i in effective_info_records]
		if index_list != sorted(index_list) or len(set(index_list)) != len(index_list):
			raise ClassInitError("Content info records has unsorted or repeated indexes")

		self._content_chunk_records = tuple([
			ContentChunkRecord(data[i:i+0x30]) for i in range(0x9C4, 0x9C4 + 0x30 * self._content_count, 0x30)
		])

		chunks = list(self._content_chunk_records)
		for i in effective_info_records:
			sha256 = hashlib.sha256(b''.join([bytes(j) for j in chunks[:i.count]])).digest()
			if sha256 != i.sha256:
				raise ClassInitError("Invalid content chunk data, sha256 mismatch")

			chunks = chunks[i.count:]

		# with enough cursed combinations it may allow repeated indexes.. but I don't wanna test it yet
		# cant test with CIA files this one
		index_list = [i.index for i in self._content_chunk_records]
		if len(set(index_list)) != len(index_list):
			raise ClassInitError("Content chunk records has repeated indexes")

		content_ids = {}
		for i in self._content_chunk_records:
			j = content_ids.get(i.id, [])
			j.append(i)
			content_ids[i.id] = j

		# because of course, content ids can be repeated, for some cursed reason
		for k in (j for i,j in content_ids.items() if len(j) > 1):
			if len(set(((l.sha256, l.size) for l in k))) > 1:
				raise ClassInitError("Repeated content ids with different size or hash detected")

		super().__init__(
			lambda: self._tmd_block[:0xC4],
			lambda: self._sign,
			lambda: self.issuer,
			lambda issuer: issuer.ljust(64,'\x00').encode() + self._tmd_block[0x40:0xC4],
			self._set_reissued
		)

	def __bytes__(self):
		return bytes(self._sign) + self._tmd_block

	def __len__(self):
		return len(self._sign) + len(self._tmd_block)

	def _set_reissued(self, sign: digsign.DigitalSignature, issuer: str, data: typing.SupportsBytes) -> None:
		self._sign = sign
		self._issuer_str = issuer
		self._tmd_block = bytes(data) + self._tmd_block[0xC4:]

	@property
	def issuer(self) -> str:
		return self._issuer_str

	@property
	def version(self) -> int:
		return self._version

	@property
	def ca_crl_version(self) -> int:
		return self._ca_crl_version

	@property
	def signed_crl_version(self) -> int:
		return self._signed_crl_version

	@property
	def system_version(self) -> int:
		return self._system_version

	@property
	def title_id(self) -> int:
		return self._title_id

	@property
	def title_type(self) -> int:
		return self._title_type

	@property
	def group_id(self) -> int:
		return self._group_id

	@property
	def save_data_size(self) -> int:
		return self._save_data_size

	@property
	def srl_private_save_data_size(self) -> int:
		return self._srl_private_save_data_size

	@property
	def srl_flag(self) -> int:
		return self._srl_flag

	@property
	def access_rights(self) -> int:
		return self._access_rights

	@property
	def title_version(self) -> int:
		return self._title_version

	@property
	def boot_content(self) -> int:
		return self._boot_content

	@property
	def chunk_info_records_sha256(self) -> bytes:
		return self._sha256_content_info_records

	@property
	def content_info_records(self) -> typing.Iterable[ContentInfoRecord]:
		return self._content_info_records

	@property
	def content_chunk_records(self) -> typing.Iterable[ContentChunkRecord]:
		return self._content_chunk_records

TitleMetaData = TMD
