import time, random, math, typing

from ._py_ver_fixes import monotonic_ns

__all__ = [
	"BootTimeEmu"
]

def monotonic_µs() -> int:
	return monotonic_ns() // 1000

class BootTimeEmu:
	def __init__(self):
		self.reboot()

	def reboot(self) -> None:
		self._boottime = monotonic_µs()
		self._nextready = self._boottime + random.randint(8000000,12000000)

	def sleep_with_rng_curve(
		self,
		sleep_min_time: typing.Union[int, float],
		rng_multiplier: typing.Union[int, float] = 1
	) -> None:
		# tMin + random() ** 2.5 * rng_multiplier
		timenow = monotonic_µs()
		t = sleep_min_time + math.pow(random.random(), 2.5) * rng_multiplier
		t_F = math.floor(t)
		remaining_last = self._nextready - timenow if self._nextready > timenow else 0
		self._nextready = timenow + t_F * 1000000 + int((t - t_F) * 1000000) + remaining_last

	@property
	def get_microseconds(self) -> int:
		time.sleep(1e-6)

		timenow = monotonic_µs()
		boottime = self._boottime
		nextready = self._nextready

		if nextready > timenow:
			time.sleep((nextready - timenow) / 1000000.0)
			timenow = monotonic_µs()

		return timenow - boottime
