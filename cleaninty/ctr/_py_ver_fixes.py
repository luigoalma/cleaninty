import sys, typing, time, math

if sys.hexversion < 0x03070000:
	def monotonic_ns() -> int:
		t = time.monotonic()
		t_F = math.floor(t)
		return t_F * 1000000000 + int((t - t_F) * 1000000000)
else:
	monotonic_ns = time.monotonic_ns

if sys.hexversion < 0x03080000:
	CTRModel_T = str
	LimitKind_T = str
else:
	CTRModel_T = typing.Literal['CTR', 'SPR', 'FTR', 'KTR', 'RED', 'JAN']
	LimitKind_T = typing.Union[ # limit kind
		# don't know at this point, idk what they were thinking
		typing.Literal['PR', 'TR', 'DR', 'SR', 'LR', 'ET'],
		str # max 4 chars
	]
