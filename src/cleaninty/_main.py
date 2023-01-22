def _main():
	import sys
	from collections import OrderedDict

	from .ctr import _main as ctr_main

	# we just support 3ds, for now:tm:
	_mains = OrderedDict()
	_mains['ctr'] = {'func': ctr_main._main, 'desc': '3DS system'}
	_mains['ktr'] = {'func': ctr_main._main, 'desc': 'New 3DS system (ctr alias)'}

	def _print_help():
		print("usage: cleaninty system [args]")
		print("")
		print("systems:")
		for i, j in _mains.items():
			print(f" {i.ljust(10)} {j['desc']}")

	if len(sys.argv) < 2:
		_print_help()
	else:
		_system = _mains.get(sys.argv[1].lower(), None)

		if not _system:
			print("Argument error: invalid system")
			print("")
			_print_help()
		else:
			_system['func'](sys.argv[2:])
