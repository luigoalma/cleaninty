import time, random
from enum import IntEnum, unique

from . import ias, ecs
from .manager import CtrSoapManager, ServiceLevel
from .exception import CTRExceptionBase

__all__ = [
	"CtrSoapCheckRegister",
	"CtrSoapSessionInit",
	"CtrSoapSessionConnect",
	"SysApps",
	"CtrSoapUseSystemApps",
	"HelperError"
]

class HelperError(CTRExceptionBase):
	"""General Helper error exception"""

def CtrSoapCheckRegister(soap_device: CtrSoapManager) -> None:
	if not isinstance(soap_device, CtrSoapManager):
		raise HelperError("Expected CtrSoapManager")

	status = ecs.GetAccountStatus(soap_device)

	status.update_soap_managers_uris()

	if soap_device.service_standby and not soap_device.is_service_ready():
		raise HelperError("Unhandled combination of service status")

	if status.errorcode == 902 or status.errorcode == 903:
		reginfo = ias.GetRegistrationInfo(soap_device, ias.GetChallenge(soap_device).challenge)

		if not reginfo.is_registered:
			soap_device.unregister_account()

		else:
			soap_device.register_account('R', reginfo.devicetoken, reginfo.accountid, reginfo.country, reginfo.extaccountid, reginfo.devicecode, reginfo.devicetokenexpired)

	elif status.errorcode != 901:
		status.validate_errorcode()

		if status.accountstatus == 'U':
			soap_device.unregister_account()
		else:
			# we are in abnormal condition compared to the actual console
			# we are foreign
			# it may change its condition
			soap_device.register_account(status.accountstatus, soap_device.st_token, status.accountid, status.country, soap_device.ext_account_id, soap_device.device_code, soap_device.register_expired)


def CtrSoapSessionInit(soap_device: CtrSoapManager) -> None:
	"""
	Partial recommended session start for EC, complete for NUP.
	It's recommended to set an AppId and TIN to the manager.
	"""

	if not isinstance(soap_device, CtrSoapManager):
		raise HelperError("Expected CtrSoapManager")

	reginfo = None

	status = ecs.GetAccountStatus(soap_device)

	status.update_soap_managers_uris()

	if soap_device.service_standby and not soap_device.is_service_ready():
		raise HelperError("Unhandled combination of service status")

	if status.errorcode == 902 or status.errorcode == 903:
		reginfo = ias.GetRegistrationInfo(soap_device, ias.GetChallenge(soap_device).challenge)

		if not reginfo.is_registered:
			soap_device.unregister_account()

		elif reginfo.devicetokenexpired:
			soap_device.country_change(reginfo.country)

			reginfo = ias.Register(soap_device, ias.GetChallenge(soap_device).challenge)

			soap_device.register_account('R', reginfo.devicetoken, reginfo.accountid, reginfo.country, reginfo.extaccountid, reginfo.devicecode)

		else:
			soap_device.register_account('R', reginfo.devicetoken, reginfo.accountid, reginfo.country, reginfo.extaccountid, reginfo.devicecode)

		if soap_device.service_level == ServiceLevel.SHOP:
			status = ecs.GetAccountStatus(soap_device)

			status.update_soap_managers_uris()

	elif status.errorcode != 901:
		status.validate_errorcode()

	if status.accountstatus == 'P':
		if reginfo is not None:
			soap_device.country_change(reginfo.country)

		reginfo = ias.AccountTransfer(soap_device, ias.GetChallenge(soap_device).challenge)

		soap_device.register_account('T', reginfo.devicetoken, reginfo.accountid, reginfo.country, reginfo.extaccountid, reginfo.devicecode)

	elif status.accountstatus == 'R' or status.accountstatus == 'T':
		soap_device.register_account(status.accountstatus, soap_device.st_token, soap_device.account_id, soap_device.country, soap_device.ext_account_id, soap_device.device_code)
	elif status.accountstatus == 'U':
		reginfo = ias.Register(soap_device, ias.GetChallenge(soap_device).challenge)

		soap_device.register_account('R', reginfo.devicetoken, reginfo.accountid, reginfo.country, reginfo.extaccountid, reginfo.devicecode)
	else:
		raise HelperError("Unknown account status indicator returned from SOAP!")

	if soap_device.service_level == ServiceLevel.SHOP:
		status = ecs.GetAccountStatus(soap_device)

		status.update_soap_managers_uris()

		soap_device.set_ivs_sync_flag(status.ivssyncflag)

	if soap_device.service_standby and not soap_device.is_service_ready():
		raise HelperError("Unhandled combination of service status")

# post transfer connect, import_remote_ivs = True
def CtrSoapSessionConnect(soap_device: CtrSoapManager, import_remote_ivs: bool = False, drop_remote_ivs: bool = True, *, forced_ivs_remote_import: bool = False, forced_ivs_send: bool = False):
	"""
	More complete init for EC manager.
	It's recommended to set an AppId and TIN to the manager.
	"""

	if forced_ivs_remote_import:
		import_remote_ivs = True

	if not isinstance(soap_device, CtrSoapManager):
		raise HelperError("Expected CtrSoapManager")

	CtrSoapSessionInit(soap_device)

	if soap_device.service_level != ServiceLevel.SHOP:
		return

	if soap_device.service_standby:
		return

	try:
		current_ivs = soap_device.export_ivs()
	except Exception:
		return

	if (soap_device.ivs_sync_flag or forced_ivs_remote_import) and not forced_ivs_send:
		if import_remote_ivs:
			remote_ivs = ias.GetIVSData(soap_device).ivsdata

			if not remote_ivs and soap_device.ivs_sync_flag:
				ias.ReportIVSSync(soap_device)

			else:
				imported = False

				try:
					soap_device.import_ivs(remote_ivs)
					imported = True
				except Exception:
					pass

				if imported and soap_device.ivs_sync_flag:
					try:
						ias.ReportIVSSync(soap_device)
					except Exception:
						soap_device.import_ivs(current_ivs)
						raise

				if imported:
					soap_device.set_last_sync_ivs(remote_ivs)

		elif drop_remote_ivs:
			ias.ReportIVSSync(soap_device)

	elif soap_device.is_msed_signed and \
		(soap_device.account_status == 'R' or soap_device.account_status == 'T'):
		last_ivs = soap_device.last_sync_ivs

		if forced_ivs_send or not last_ivs or current_ivs != last_ivs:
			ias.SetIVSData(soap_device, current_ivs)

			soap_device.set_last_sync_ivs(current_ivs)

@unique
class SysApps(IntEnum):
	NIM = 0
	ESHOP = 1
	SYSTRANSFER = 2

def CtrSoapUseSystemApps(soap_device: CtrSoapManager, app: SysApps) -> None:
	if not isinstance(soap_device, CtrSoapManager):
		raise HelperError("Expected CtrSoapManager")

	if app == SysApps.NIM:
		soap_device.set_app_and_tin(0x0004013000002C02, 1234)

	elif app == SysApps.ESHOP:
		tid = {
			'JPN': 0x0004001000020900,
			'USA': 0x0004001000021900,
			'EUR': 0x0004001000022900,
			'KOR': 0x0004001000027900,
			'TWN': 0x0004001000028900
		}.get(soap_device.region, None)

		if tid is None:
			raise HelperError("eShop not available on this region or region invalid")

		soap_device.set_app_and_tin(tid, 56789)

	elif app == SysApps.SYSTRANSFER:
		tid = {
			'JPN': 0x0004001000020A00,
			'USA': 0x0004001000021A00,
			'EUR': 0x0004001000022A00,
			'KOR': 0x0004001000027A00,
			'TWN': 0x0004001000028A00
		}.get(soap_device.region, None)

		if tid is None:
			raise HelperError("System transfer not available on this region or region invalid")

		soap_device.set_app_and_tin(tid, 1111)
