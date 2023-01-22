
__all__ = [
	"CleanintyExceptionBase",
	"ModuleInitError",
	"ClassInitError",
	"DataProcessingError"
]

class CleanintyExceptionBase(Exception):
	"""Base exception for all module specific exceptions"""

class ModuleInitError(CleanintyExceptionBase):
	"""Exception related to module initialization"""

class ClassInitError(CleanintyExceptionBase):
	"""Exception related to class initialization"""

class DataProcessingError(CleanintyExceptionBase):
	"""Exception related to error processing data"""

