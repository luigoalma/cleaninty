__version__ = '0.1.2'
__author__ = 'Luis Marques'
__license__ = 'Unlicense'

from . import exception

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

if not default_backend().elliptic_curve_supported(ec.SECT233R1()):
	raise exception.ModuleInitError("cryptography's default backend does not support sect233r1!")

del ec
del default_backend
del exception
