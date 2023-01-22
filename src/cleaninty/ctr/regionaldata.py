from enum import IntEnum, unique
import typing

__all__ = [
	"Region",
	"Country",
	"Language"
]

@unique
class Region(IntEnum):
	JPN = 0
	USA = 1
	EUR = 2
	AUS = 3
	CHN = 4
	KOR = 5
	TWN = 6

	@classmethod
	def get_region(
		cls,
		value: typing.Union['Region', typing.SupportsInt, str]
	) -> typing.Union['Region', None]:
		try:
			if isinstance(value, str):
				return getattr(cls, value[:3].upper())
			else:
				return cls(int(value))
		except:
			return None

	@classmethod
	def get_region_str(
		cls,
		value: typing.Union['Region', typing.SupportsInt, str]
	) -> typing.Union[str, None]:
		region = cls.get_region(value)
		return region.name if region is not None else None

@unique
class Country(IntEnum):
	JP = 1   # Japan
	AI = 8   # Anguilla
	AG = 9   # Antigua and Barbuda
	AR = 10  # Argentina
	AW = 11  # Aruba
	BS = 12  # Bahamas
	BB = 13  # Barbados
	BZ = 14  # Belize
	BO = 15  # Bolivia
	BR = 16  # Brazil
	VG = 17  # British Virgin Islands
	CA = 18  # Canada
	KY = 19  # Cayman Islands
	CL = 20  # Chile
	CO = 21  # Colombia
	CR = 22  # Costa Rica
	DM = 23  # Dominica
	DO = 24  # Dominican Republic
	EC = 25  # Ecuador
	SV = 26  # El Salvador
	GF = 27  # French Guiana
	GD = 28  # Grenada
	GP = 29  # Guadeloupe
	GT = 30  # Guatemala
	GY = 31  # Guyana
	HT = 32  # Haiti
	HN = 33  # Honduras
	JM = 34  # Jamaica
	MQ = 35  # Martinique
	MX = 36  # Mexico
	MS = 37  # Montserrat
	AN = 38  # Netherlands Antilles
	NI = 39  # Nicaragua
	PA = 40  # Panama
	PY = 41  # Paraguay
	PE = 42  # Peru
	KN = 43  # Saint Kitts and Nevis
	LC = 44  # Saint Lucia
	VC = 45  # Saint Vincent and the Grenadines
	SR = 46  # Suriname
	TT = 47  # Trinidad and Tobago
	TC = 48  # Turks and Caicos Islands
	US = 49  # United States
	UY = 50  # Uruguay
	VI = 51  # US Virgin Islands
	VE = 52  # Venezuela
	AL = 64  # Albania
	AU = 65  # Australia
	AT = 66  # Austria
	BE = 67  # Belgium
	BA = 68  # Bosnia and Herzegovina
	BW = 69  # Botswana
	BG = 70  # Bulgaria
	HR = 71  # Croatia
	CY = 72  # Cyprus
	CZ = 73  # Czech Republic
	DK = 74  # Denmark
	EE = 75  # Estonia
	FI = 76  # Finland
	FR = 77  # France
	DE = 78  # Germany
	GR = 79  # Greece
	HU = 80  # Hungary
	IS = 81  # Iceland
	IE = 82  # Ireland
	IT = 83  # Italy
	LV = 84  # Latvia
	LS = 85  # Lesotho
	LI = 86  # Liechtenstein
	LT = 87  # Lithuania
	LU = 88  # Luxembourg
	MK = 89  # Macedonia
	MT = 90  # Malta
	ME = 91  # Montenegro
	MZ = 92  # Mozambique
	NA = 93  # Namibia
	NL = 94  # Netherlands
	NZ = 95  # New Zealand
	NO = 96  # Norway
	PL = 97  # Poland
	PT = 98  # Portugal
	RO = 99  # Romania
	RU = 100 # Russia
	RS = 101 # Serbia and Kosovo
	SK = 102 # Slovakia
	SI = 103 # Slovenia
	ZA = 104 # South Africa
	ES = 105 # Spain
	SZ = 106 # Swaziland
	SE = 107 # Sweden
	CH = 108 # Switzerland
	TR = 109 # Turkey
	GB = 110 # United Kingdom
	ZM = 111 # Zambia
	ZW = 112 # Zimbabwe
	AZ = 113 # Azerbaijan
	MR = 114 # Mauritania
	ML = 115 # Mali
	NE = 116 # Niger
	TD = 117 # Chad
	SD = 118 # Sudan
	ER = 119 # Eritrea
	DJ = 120 # Djibouti
	SO = 121 # Somalia
	AD = 122 # Andorra
	GI = 123 # Gibraltar
	GG = 124 # Guernsey
	IM = 125 # Isle of Man
	JE = 126 # Jersey
	MC = 127 # Monaco
	TW = 128 # Taiwan
	KR = 136 # South Korea
	HK = 144 # Hong Kong
	MO = 145 # Macau
	ID = 152 # Indonesia
	SG = 153 # Singapore
	TH = 154 # Thailand
	PH = 155 # Philippines
	MY = 156 # Malaysia
	CN = 160 # China
	AE = 168 # United Arab Emirates
	IN = 169 # India
	EG = 170 # Egypt
	OM = 171 # Oman
	QA = 172 # Qatar
	KW = 173 # Kuwait
	SA = 174 # Saudi Arabia
	SY = 175 # Syria
	BH = 176 # Bahrain
	JO = 177 # Jordan
	SM = 184 # San Marino
	VA = 185 # Vatican City
	BM = 186 # Bermuda

	@classmethod
	def get_country(
		cls,
		value: typing.Union['Country', typing.SupportsInt, str]
	) -> typing.Union['Country', None]:
		try:
			if isinstance(value, str):
				return getattr(cls, value[:2].upper())
			else:
				return cls(int(value))
		except:
			return None

	@classmethod
	def get_country_str(
		cls,
		value: typing.Union['Country', typing.SupportsInt, str]
	) -> typing.Union[str, None]:
		country = cls.get_country(value)
		return country.name if country is not None else None

	@classmethod
	def get_region_country_list(
		cls,
		region: typing.Union[Region, typing.SupportsInt, str]
	) -> typing.Union[typing.Iterable['Country'], None]:
		region = Region.get_region(region)
		if region is None:
			return None
		if region == Region.JPN:
			return (cls.JP,)
		if region == Region.USA:
			return (cls.AI, cls.AG, cls.AR, cls.AW, cls.BS, cls.BB, cls.BZ, cls.BM, cls.BO, cls.BR, cls.VG, cls.CA, cls.KY, cls.CL, cls.CO, cls.CR, cls.DM, cls.DO, cls.EC, cls.SV, cls.GF, cls.GD, cls.GP, cls.GT, cls.GY, cls.HT, cls.HN, cls.JM, cls.MY, cls.MQ, cls.MX, cls.MS, cls.AN, cls.NI, cls.PA, cls.PY, cls.PE, cls.SA, cls.SG, cls.KN, cls.LC, cls.VC, cls.SR, cls.TT, cls.TC, cls.AE, cls.US, cls.UY, cls.VI, cls.VE)
		if region == Region.EUR:
			return (cls.AL, cls.AD, cls.AU, cls.AT, cls.AZ, cls.BE, cls.BA, cls.BW, cls.BG, cls.TD, cls.HR, cls.CY, cls.CZ, cls.DK, cls.DJ, cls.ER, cls.EE, cls.FI, cls.FR, cls.DE, cls.GI, cls.GR, cls.GG, cls.HU, cls.IS, cls.IN, cls.IE, cls.IM, cls.IT, cls.JE, cls.LV, cls.LS, cls.LI, cls.LT, cls.LU, cls.MK, cls.ML, cls.MT, cls.MR, cls.MC, cls.ME, cls.MZ, cls.NA, cls.NL, cls.NZ, cls.NE, cls.NO, cls.PL, cls.PT, cls.RO, cls.RU, cls.SM, cls.RS, cls.SK, cls.SI, cls.SO, cls.ZA, cls.ES, cls.SD, cls.SZ, cls.SE, cls.CH, cls.TR, cls.GB, cls.VA, cls.ZM, cls.ZW)
		if region == Region.CHN:
			return (cls.CN,)
		if region == Region.KOR:
			return (cls.KR,)
		if region == Region.TWN:
			return (cls.TW, cls.HK)
		return None

	@classmethod
	def get_unknown_region_country_list(cls) -> typing.Iterable['Country']:
		return (cls.MO, cls.ID, cls.TH, cls.PH, cls.EG, cls.OM, cls.QA, cls.KW, cls.SY, cls.BH, cls.JO)

	@classmethod
	def get_region_by_country(
		cls,
		value: typing.Union['Country', typing.SupportsInt, str]
	) -> typing.Union[Region, None]:
		country = cls.get_country(value)
		if country is None:
			return None
		if country in (cls.JP,):
			return Region.JPN
		if country in (cls.AI, cls.AG, cls.AR, cls.AW, cls.BS, cls.BB, cls.BZ, cls.BM, cls.BO, cls.BR, cls.VG, cls.CA, cls.KY, cls.CL, cls.CO, cls.CR, cls.DM, cls.DO, cls.EC, cls.SV, cls.GF, cls.GD, cls.GP, cls.GT, cls.GY, cls.HT, cls.HN, cls.JM, cls.MY, cls.MQ, cls.MX, cls.MS, cls.AN, cls.NI, cls.PA, cls.PY, cls.PE, cls.SA, cls.SG, cls.KN, cls.LC, cls.VC, cls.SR, cls.TT, cls.TC, cls.AE, cls.US, cls.UY, cls.VI, cls.VE):
			return Region.USA
		if country in (cls.AL, cls.AD, cls.AU, cls.AT, cls.AZ, cls.BE, cls.BA, cls.BW, cls.BG, cls.TD, cls.HR, cls.CY, cls.CZ, cls.DK, cls.DJ, cls.ER, cls.EE, cls.FI, cls.FR, cls.DE, cls.GI, cls.GR, cls.GG, cls.HU, cls.IS, cls.IN, cls.IE, cls.IM, cls.IT, cls.JE, cls.LV, cls.LS, cls.LI, cls.LT, cls.LU, cls.MK, cls.ML, cls.MT, cls.MR, cls.MC, cls.ME, cls.MZ, cls.NA, cls.NL, cls.NZ, cls.NE, cls.NO, cls.PL, cls.PT, cls.RO, cls.RU, cls.SM, cls.RS, cls.SK, cls.SI, cls.SO, cls.ZA, cls.ES, cls.SD, cls.SZ, cls.SE, cls.CH, cls.TR, cls.GB, cls.VA, cls.ZM, cls.ZW):
			return Region.EUR
		if country in (cls.CN,):
			return Region.CHN
		if country in (cls.KR,):
			return Region.KOR
		if country in (cls.TW, cls.HK):
			return Region.TWN
		return None

@unique
class Language(IntEnum):
	JA = 0 # japanese
	EN = 1 # english
	FR = 2 # french
	DE = 3 # german
	IT = 4 # italian
	ES = 5 # spanish
	ZH = 6 # simplified chinese
	KO = 7 # korean
	NL = 8 # dutch
	PT = 9 # portuguese
	RU = 10 # russian
	ZH_TRAD = 11 # traditional chinese

	@classmethod
	def get_language(
		cls,
		value: typing.Union['Language', typing.SupportsInt, str]
	) -> typing.Union['Language', None]:
		try:
			if isinstance(value, str):
				return getattr(cls, value[:7].upper())
			else:
				return cls(int(value))
		except:
			return None

	@classmethod
	def get_language_str(
		cls,
		value: typing.Union['Language', typing.SupportsInt, str]
	) -> typing.Union[str, None]:
		language = cls.get_language(value)
		return language.name[:2].lower() if language is not None else None

	@classmethod
	def get_region_language_list(
		cls,
		region: typing.Union[Region, typing.SupportsInt, str]
	) -> typing.Union[typing.Iterable['Language'], None]:
		region = Region.get_region(region)
		if region is None:
			return None
		if region == Region.JPN:
			return (cls.JA,)
		if region == Region.CHN:
			return (cls.ZH,)
		if region == Region.KOR:
			return (cls.KO,)
		if region == Region.TWN:
			return (cls.ZH_TRAD,)
		if region == Region.USA:
			return (cls.EN, cls.FR, cls.ES, cls.PT)
		if region == Region.EUR:
			return (cls.EN, cls.FR, cls.DE, cls.ES, cls.IT, cls.NL, cls.PT, cls.RU)
		return None

RegionType = typing.Union[Region, typing.SupportsInt, str]
CountryType = typing.Union[Country, typing.SupportsInt, str]
LanguageType = typing.Union[Language, typing.SupportsInt, str]
