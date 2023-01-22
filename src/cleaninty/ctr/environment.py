import pathlib, typing

from ._env import *

__all__ = ['find_in_config_dirs']

def find_in_config_dirs(filepath: str, create_missing: bool = False) -> typing.List[str]:
	filepath = str(filepath)

	paths = []

	for i in config_dirs:
		try:
			path = (pathlib.Path(i) / filepath).resolve()
			if not path.is_file():
				continue

			paths.append(str(path))

		except Exception:
			pass

	if not paths and create_missing:
		for i in config_dirs:
			try:
				path = (pathlib.Path(i) / filepath).resolve()
				if not path.exists():
					path.parent.mkdir(parents=True, exist_ok=True)
					path.touch()

				if not path.is_file():
					continue

				paths.append(str(path))
				break

			except Exception:
				pass

	return list(set(paths))
