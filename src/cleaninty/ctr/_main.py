import argparse, pathlib, sys, json, datetime

from .simpledevice import SimpleCtrDevice
from .soap.manager import CtrSoapManager
from .soap import ias, ecs, helpers
from .ninja import NinjaManager, NinjaException
from .act import ActSimpleObj
from .title import Title, MediaType
from ..nintendowifi.soapenvelopebase import SoapCodeError
from .secureinfo import SecureInfo
from .cdn import CDN
from .cdn_helpers import CiaCDNBuilder
from . import regionaldata, keys, constants

def _print_unhandled_exceptions(func):
	def inner(*args, **kwds):
		try:
			return func(*args, **kwds)
		except Exception as e:
			print(f'An exception occurred:\n - {type(e).__name__}:\n  - {e}')
	return inner

def _print_soapcode_exceptions(func):
	def inner(*args, **kwds):
		try:
			return func(*args, **kwds)
		except SoapCodeError as e:
			print('A SoapCodeError was raised:')
			print(f' Exception args: {str(e)}')
			print(f' Soap error code: {e.soaperrorcode}')
			print(f' Soap error message: {e.soaperrormessage}')
	return inner

@_print_unhandled_exceptions
def _setup_constants(parser, parsed_args):
	if parsed_args.aes_constant_c:
		c = None
		try:
			c = bytes.fromhex(parsed_args.aes_constant_c)
		except Exception:
			pass
		constants._load_const_c(c)
	if parsed_args.ssl:
		constants._configure_certs(parsed_args.ssl.read(4*1024*1024))
	if parsed_args.cfg:
		constants._load_cfg_rsa_keys(parsed_args.cfg.read(4*1024*1024))
	if parsed_args.act:
		constants._load_act_secrets(parsed_args.act.read(4*1024*1024))
	if parsed_args.process9:
		constants._load_p9_keys(parsed_args.process9.read(4*1024*1024))
	if parsed_args.enc_clcert_cert and parsed_args.enc_clcert_key:
		constants._configure_cli_cert_and_key(
			parsed_args.enc_clcert_cert.read(64*1024),
			parsed_args.enc_clcert_key.read(64*1024)
		)

	print("If any valid data was found, respective constants were setup.")

@_print_unhandled_exceptions
def _gen_json(parser, parsed_args):
	print("Generating json...")

	SimpleCtrDevice.generate_new_json(
		otp_fp=parsed_args.otp,
		secureinfo_fp=parsed_args.secureinfo,
		serialnumber=parsed_args.serialnumber,
		msed_fp=parsed_args.msed,
		model_override=parsed_args.model,
		region=parsed_args.region,
		country=parsed_args.country,
		language=parsed_args.language,
		json_file=parsed_args.out
	)

	print("Complete!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _move_account(parser, parsed_args):
	print("Initializing source console...")
	source = SimpleCtrDevice(json_file=parsed_args.source)
	soap_source = CtrSoapManager(source, False)

	print("Initializing target console...")
	target = SimpleCtrDevice(json_file=parsed_args.target)
	soap_target = CtrSoapManager(target, False)

	helpers.CtrSoapUseSystemApps(soap_source, helpers.SysApps.SYSTRANSFER)
	helpers.CtrSoapUseSystemApps(soap_target, helpers.SysApps.SYSTRANSFER)

	print("Initializing console sessions...")
	helpers.CtrSoapSessionConnect(soap_source)
	helpers.CtrSoapSessionConnect(soap_target)

	print("Saving updated sessions...")
	source.serialize_json(json_file=parsed_args.source)
	target.serialize_json(json_file=parsed_args.target)

	print("Checking if we can move account...")
	movestatus = ias.MoveAccount(
		soap_source,
		soap_target.device_id,
		soap_target.account_id,
		soap_target.st_token,
		True
	)

	print("Performing move...")
	movestatus = ias.MoveAccount(
		soap_source,
		soap_target.device_id,
		soap_target.account_id,
		soap_target.st_token,
		False
	)

	print("Complete!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _move_nnid(parser, parsed_args):
	print("Initializing source console...")
	source = SimpleCtrDevice(json_file=parsed_args.source)
	soap_source = CtrSoapManager(source, False)

	print("Initializing target console...")
	target = SimpleCtrDevice(json_file=parsed_args.target)
	soap_target = CtrSoapManager(target, False)

	helpers.CtrSoapUseSystemApps(soap_source, helpers.SysApps.SYSTRANSFER)
	helpers.CtrSoapUseSystemApps(soap_target, helpers.SysApps.SYSTRANSFER)

	print("Initializing console sessions...")
	helpers.CtrSoapSessionConnect(soap_source)
	helpers.CtrSoapSessionConnect(soap_target)

	print("Saving updated sessions...")
	source.serialize_json(json_file=parsed_args.source)
	target.serialize_json(json_file=parsed_args.target)

	print("Attempt to move NNID")
	act_source = ActSimpleObj(
		source,
		source.titles(MediaType.NAND)[
			source.titles(MediaType.NAND).index(soap_source.application_id)
		]
	)
	act_target = ActSimpleObj(
		target,
		target.titles(MediaType.NAND)[
			target.titles(MediaType.NAND).index(soap_target.application_id)
		]
	)

	http, response = act_source.devices_current_migrations_commit()
	if (http // 100) == 2 and not response.had_errors:
		http, response = act_source.devices_current_migrations(delete=True)
	if (http // 100) == 2 and not response.had_errors:
		http, response = act_source.devices_current_migrations(
			delete=False,
			serialnumber=target.serial_no,
			deviceid=target.device_id
		)
	if (http // 100) == 2 and not response.had_errors:
		http, response = act_target.devices_current_migrations_commit()
	if (http // 100) != 2 or response.had_errors:
		print("Fail!")
		print(f"http response: {http}")
		print("")
		for i in response.errors:
			print("account api error response:")
			print(f"- cause: {i.cause}")
			print(f"- code: {i.code}")
			print(f"- message: {i.message}")
			print("")
		return

	print("Complete!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _move_check_account(parser, parsed_args):
	print("Initializing console...")
	device = SimpleCtrDevice(json_file=parsed_args.console)
	soap_device = CtrSoapManager(device, False)

	print("Checking registry...")
	helpers.CtrSoapCheckRegister(soap_device)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	acct_attributes = ias.GetAccountAttributesByProfile(soap_device, 'MOVE_ACCT')

	moved_times = None
	moved_last_time = None

	for i in acct_attributes.accountattributes:
		if   i[0] == 'MoveAccountTimes':
			moved_times = int(i[1]) if i[1] else 0
		elif i[0] == 'MoveAccountLastMovedDate':
			moved_last_time = int(i[1]) if i[1] else 0

	utc_0 = datetime.datetime.utcfromtimestamp(0)

	server_time = utc_0 + datetime.timedelta(milliseconds=acct_attributes.timestamp)
	if moved_last_time is not None:
		moved_last_time = utc_0 + datetime.timedelta(milliseconds=moved_last_time)
		time_ready_for_new_move = moved_last_time + datetime.timedelta(days=7)

	if moved_times is not None:
		print(f"Moved times: {moved_times}")
	else:
		print("No moved times info!")

	if moved_last_time is not None:
		print(f"Moved last date: {moved_last_time.strftime('%a, %d %b %Y %H:%M:%S UTC')}")
	else:
		print("No moved last date info!")

	print(f"Server time at response: {server_time.strftime('%a, %d %b %Y %H:%M:%S UTC')}")

	if moved_last_time is not None and time_ready_for_new_move > server_time:
		delta = time_ready_for_new_move - server_time
		d = delta.days
		h = delta.seconds // 3600
		m = delta.seconds // 60 % 60
		s = delta.seconds % 60
		μs = delta.microseconds
		print(f"Ready for transfer in {d}d {h}h {m}min {s}s {μs}μs")
		print(f"Ready at: {time_ready_for_new_move.strftime('%a, %d %b %Y %H:%M:%S UTC')}")
	else:
		print("Ready for transfer!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _get_ivs(parser, parsed_args):
	print("Initializing console...")
	device = SimpleCtrDevice(json_file=parsed_args.console)
	soap_device = CtrSoapManager(device, False)

	print("Initializing console session with forced get ivs...")
	helpers.CtrSoapSessionConnect(soap_device, forced_ivs_remote_import=True)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	print("Complete!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _set_ivs(parser, parsed_args):
	print("Initializing console...")
	device = SimpleCtrDevice(json_file=parsed_args.console)
	soap_device = CtrSoapManager(device, False)

	print("Initializing console session with forced set ivs...")
	helpers.CtrSoapSessionConnect(soap_device, forced_ivs_send=True)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	print("Complete!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _recover_ivs_otp(parsed, parsed_args):
	print("Generating json serialless in memory...")

	c = SimpleCtrDevice.generate_new_json(
		otp_fp=parsed_args.otp,
		serialnumber='XXX12345678',
		region=parsed_args.region,
		country=parsed_args.country,
		language=parsed_args.language
	)

	print("Initializing console...")
	device = SimpleCtrDevice(json_string=c)
	soap_device = CtrSoapManager(device, False)

	print("Attempt movable.sed recovery...")
	reginfo = ias.GetRegistrationInfo(soap_device, ias.GetChallenge(soap_device).challenge)

	if not reginfo.is_registered:
		print("Cannot recover, no registry.")
		return

	elif reginfo.devicetokenexpired:
		print("Cannot recover, device token expired.")
		return

	soap_device.register_account('R', reginfo.devicetoken, reginfo.accountid, reginfo.country, reginfo.extaccountid, reginfo.devicecode)

	remote_ivs = ias.GetIVSData(soap_device).ivsdata

	if not remote_ivs:
		print("Cannot recover, no IVS found.")
		return

	soap_device.import_ivs(remote_ivs)

	print("Saving Movable.sed...")
	with open(parsed_args.out, 'wb') as o:
		o.write(bytes(device.msed))

	print("Complete!")

def _run_unregister(device, soap_device):
	try:
		ias.Unregister(soap_device, ias.GetChallenge(soap_device).challenge)
		soap_device.unregister_account()
		virtual = False
	except SoapCodeError as e:
		if e.soaperrorcode != 434:
			raise
		virtual = True

	if virtual:
		print("Virtual account link! Attempt detach by error...")
		device.reboot()

		print("Initializing console session...")
		helpers.CtrSoapUseSystemApps(soap_device, helpers.SysApps.SYSTRANSFER)
		helpers.CtrSoapSessionConnect(soap_device)

		device_ninja = NinjaManager(soap_device)
		try:
			device_ninja.open_without_nna()
		except NinjaException as e:
			if e.errorcode != 3136:
				raise

		device.reboot()

		print("Initializing console...")
		helpers.CtrSoapUseSystemApps(soap_device, helpers.SysApps.ESHOP)

		print("Checking registry...")
		helpers.CtrSoapCheckRegister(soap_device)

		if soap_device.account_status != 'U':
			print("Unregister...")
			ias.Unregister(soap_device, ias.GetChallenge(soap_device).challenge)
			soap_device.unregister_account()
		else:
			print("Unregistered!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _del_eshop(parser, parsed_args):
	print("Initializing console...")
	device = SimpleCtrDevice(json_file=parsed_args.console)
	soap_device = CtrSoapManager(device, False)

	print("Checking registry...")
	helpers.CtrSoapCheckRegister(soap_device)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	if soap_device.account_status == 'U':
		print("Console already does not have EShop account.")
		return

	device.reboot()

	print("Initializing console session...")
	helpers.CtrSoapUseSystemApps(soap_device, helpers.SysApps.ESHOP)
	helpers.CtrSoapSessionConnect(soap_device)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	print("Unregister...")
	_run_unregister(device, soap_device)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	print("Complete!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _eshop_region_change(parser, parsed_args):
	print("Initializing console...")
	device = SimpleCtrDevice(json_file=parsed_args.console)
	soap_device = CtrSoapManager(device, False)

	print("Checking registry...")
	helpers.CtrSoapCheckRegister(soap_device)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	if parsed_args.region == soap_device.region and soap_device.account_status != 'U':
		print("Console already in the desired region.")
		return

	device.reboot()

	if soap_device.account_status != 'U':
		print("Initializing console session...")
		helpers.CtrSoapUseSystemApps(soap_device, helpers.SysApps.ESHOP)
		helpers.CtrSoapSessionConnect(soap_device)

		print("Saving updated session...")
		device.serialize_json(json_file=parsed_args.console)

		print("Unregister...")
		_run_unregister(device, soap_device)

		print("Saving updated session...")
		device.serialize_json(json_file=parsed_args.console)

		device.reboot()

	soap_device.region_change(parsed_args.region, parsed_args.country, parsed_args.language)

	print("Initializing console session...")
	helpers.CtrSoapUseSystemApps(soap_device, helpers.SysApps.ESHOP)
	try:
		helpers.CtrSoapSessionConnect(soap_device)
	except SoapCodeError as e:
		if e.soaperrorcode == 602:
			print("We got soap error 602.")
			print("Region could not be changed.")
			print("Any existing eshop account was deleted in the process.")
			print("This console has titles attached to it on a different region.")
			print("System transfer to another console is needed to remove them.")
			print("System transfer without NNID transfer is enough.")
			print("NNID-only transfers do not work to fix.")
			return
		raise

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	print("Complete!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _list_etickets(parser, parsed_args):
	_format = parsed_args.format.lower()
	if _format not in ['text', 'json']:
		parser.error("Invalid output format.")
		return

	print("Initializing console...")
	device = SimpleCtrDevice(json_file=parsed_args.console)
	soap_device = CtrSoapManager(device, False)

	print("Initializing console session...")
	helpers.CtrSoapUseSystemApps(soap_device, helpers.SysApps.ESHOP)
	helpers.CtrSoapSessionConnect(soap_device)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	accountetickets = ecs.AccountListETicketIds(soap_device)

	tivs = []
	for i in accountetickets.tivs:
		tivs.append(i[0])

	accountetickets = ecs.AccountGetETicketDetails(soap_device, tivs)

	out = parsed_args.out
	out = out.open('w', encoding='utf-8') if out else sys.stdout

	if _format == 'text':
		out.write(f"Total ETickets: {len(accountetickets.eticketinfos)}\n")
		for i in accountetickets.eticketinfos:
			out.write("ETicketInfo:\n")
			out.write(f" - TicketId: {i.ticketid}\n")
			out.write(f" - TitleId: {i.titleid:016X}\n")
			out.write(f" - Version: {i.version}\n")
			out.write(f" - FormatVersion: {i.formatversion}\n")
			out.write(f" - MigrationCount: {i.migratecount}\n")
			out.write(f" - MigrationLimit: {i.migratelimit}\n")
			out.write(f" - EstimatedSize: {i.estimatedsize}\n")
	elif _format == 'json':
		json.dump(
			{'ETicketInfos': accountetickets.eticketinfos},
			out,
			indent=2,
			default=lambda x: x.__dict__
		)
		print("")

	if out is not sys.stdout:
		out.close()

	print("Complete!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _check_register(parser, parsed_args):
	print("Initializing console...")
	device = SimpleCtrDevice(json_file=parsed_args.console)
	soap_device = CtrSoapManager(device, False)

	print("Checking registry...")
	helpers.CtrSoapCheckRegister(soap_device)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	print(f"Account status: {soap_device.account_status}")
	if soap_device.account_status != 'U':
		print(f"Account register: {'Expired' if soap_device.register_expired else 'Valid'}")
	print(f"Current effective region: {soap_device.region}")
	print(f"Current effective country: {soap_device.country}")
	print(f"Current effective language: {soap_device.language}")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _download_etickets(parser, parsed_args):
	if parsed_args.ticket_id and not parsed_args.all:
		_tikids = sum(parsed_args.ticket_id, [])
		tikids = []
		for i in _tikids:
			try:
				tikids.append(int(i))
			except Exception:
				pass
		del _tikids
		if not tikids:
			print("No valid ticket ids received and --all is unset.")
			return

	print("Initializing console...")
	device = SimpleCtrDevice(json_file=parsed_args.console)
	soap_device = CtrSoapManager(device, False)

	print("Initializing console session...")
	helpers.CtrSoapUseSystemApps(soap_device, helpers.SysApps.ESHOP)
	helpers.CtrSoapSessionConnect(soap_device)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	accountetickets = ecs.AccountListETicketIds(soap_device)

	account_tivs = []
	for i in accountetickets.tivs:
		account_tivs.append(i[0])

	if parsed_args.all:
		tikids = account_tivs
	else:
		tikids = list(set(tikids).intersection(account_tivs))

	if not tikids:
		print("No ticket ids were found to download.")
		return

	etiks = []
	certs = []

	print("Fetching Tickets...")

	try:
		parsed_args.out.mkdir(parents=True, exist_ok=True)
	except Exception:
		print("Failed to ensure output path.")
		return

	for i in tikids:
		# yes, AccountGetETickets can actually take multiple ids.
		# but 3ds does not do that.
		etik = ecs.AccountGetETickets(soap_device, [i])
		etiks += list(etik.etickets)
		certs += list(etik.certs)
		certs = list(set(etik.certs))

	print(f"Saving {len(etiks)} tickets and {len(certs)} certs...")

	for i in etiks:
		out_name = f"{i.title_id:016X}.{i.ticket_id}.{i.device_id:08X}.{i.eshop_id:08X}.tik"
		out_path = parsed_args.out / out_name
		try:
			with out_path.open('wb') as o:
				o.write(bytes(i) if parsed_args.decrypt else i.installable_export)
		except Exception as e:
			print("Failed to write " + out_name)
			print(type(e), e)

	for i in certs:
		out_name = f"{i.full_issuer}.bin"
		out_path = parsed_args.out / out_name
		try:
			with out_path.open('wb') as o:
				o.write(bytes(i))
		except Exception as e:
			print("Failed to write " + out_name)
			print(type(e), e)

	print("Done!")

@_print_unhandled_exceptions
@_print_soapcode_exceptions
def _download_title_tikid(parser, parsed_args):
	if parsed_args.ticket_id and not parsed_args.all:
		_tikids = sum(parsed_args.ticket_id, [])
		tikids = []
		for i in _tikids:
			try:
				tikids.append(int(i))
			except Exception:
				pass
		del _tikids
		if not tikids:
			print("No valid ticket ids received and --all is unset.")
			return

	print("Initializing console...")
	device = SimpleCtrDevice(json_file=parsed_args.console)
	soap_device = CtrSoapManager(device, False)

	print("Initializing console session...")
	helpers.CtrSoapUseSystemApps(soap_device, helpers.SysApps.ESHOP)
	helpers.CtrSoapSessionConnect(soap_device)

	print("Saving updated session...")
	device.serialize_json(json_file=parsed_args.console)

	accountetickets = ecs.AccountListETicketIds(soap_device)

	account_tivs = []
	for i in accountetickets.tivs:
		account_tivs.append(i[0])

	if parsed_args.all:
		tikids = account_tivs
	else:
		tikids = list(set(tikids).intersection(account_tivs))

	if not tikids:
		print("No ticket ids were found to download.")
		return

	etiks = []
	certs = {}

	print("Fetching tickets...")

	try:
		parsed_args.out.mkdir(parents=True, exist_ok=True)
	except Exception:
		print("Failed to ensure output path.")
		return

	for i in tikids:
		# yes, AccountGetETickets can actually take multiple ids.
		# but 3ds does not do that.
		etik = ecs.AccountGetETickets(soap_device, [i])
		etiks += list(etik.etickets)
		_certs = list(set(etik.certs))
		for j in _certs:
			certs[j.full_issuer] = j

	print(f"Downloading {len(etiks)} titles...")

	for i in etiks:
		cdn = CDN(
			i.title_id, 
			device_id=i.device_id,
			account_id=i.eshop_id,
			ticket=i,
			content_prefix=soap_device.get_url_by_identifier('content_prefix'),
			uncached_content_prefix=soap_device.get_url_by_identifier('uncached_content_prefix'),
			system_content_prefix=soap_device.get_url_by_identifier('system_content_prefix'),
			system_uncached_content_prefix=soap_device.get_url_by_identifier('system_uncached_content_prefix'),
			is_dev=device.is_dev
		)

		cert = certs.get(i.issuer, None)
		while cert:
			cdn.add_additional_cert(cert)
			cert = certs.get(cert.issuer, None)

		out_name = f"{i.title_id:016X}.{i.ticket_id}.{i.device_id:08X}.{i.eshop_id:08X}.cia"
		out_path = parsed_args.out / out_name

		print(f"Downloading to {out_name}")
		try:
			helper = CiaCDNBuilder(str(out_path))
			if not cdn.download(helper, right_check=not parsed_args.ignore_rights):
				print("Failed to download to " + out_name)
				print("This may happen with connection errors, missing content or other unexpected reasons")
		except Exception as e:
			print("Failed to download to " + out_name)
			print(type(e), e)
			raise

	print("Done!")

def _main(args = None):
	parser = argparse.ArgumentParser(prog='cleaninty.ctr')
	parser.add_argument(
		'--boot9',
		help='3DS\'S boot9 for keys if not on the environment',
		type=str
	)

	subparsers = parser.add_subparsers(required=True, metavar='command')

	constants_parser = subparsers.add_parser('SetupConstants', help='Setup various used constants to environment')
	constants_parser.add_argument(
		'--aes-constant-c',
		help='Hardware AES Constant C as an hex string',
		type=str
	)
	constants_parser.add_argument(
		'--ssl',
		help='Path to SSL Module\'s code.bin',
		type=argparse.FileType('rb')
	)
	constants_parser.add_argument(
		'--cfg',
		help='Path to CFG Module\'s code.bin',
		type=argparse.FileType('rb')
	)
	constants_parser.add_argument(
		'--act',
		help='Path to ACT Module\'s code.bin',
		type=argparse.FileType('rb')
	)
	constants_parser.add_argument(
		'--process9',
		help='Path to Process9\'s code.bin',
		type=argparse.FileType('rb')
	)
	constants_parser.add_argument(
		'--enc-clcert-cert',
		help='Path to ClCertA\'s ctr-common-1-cert.bin',
		type=argparse.FileType('rb')
	)
	constants_parser.add_argument(
		'--enc-clcert-key',
		help='Path to ClCertA\'s ctr-common-1-key.bin',
		type=argparse.FileType('rb')
	)
	constants_parser.set_defaults(func=_setup_constants)

	gen_parser = subparsers.add_parser('GenJson', help='Generate Console JSON Object')
	gen_parser.add_argument(
		'--otp',
		help='Console\'s encrypted or decrypted otp file',
		required=True,
		type=argparse.FileType('rb')
	)
	gen_secinfo_parser = gen_parser.add_mutually_exclusive_group(required=True)
	gen_secinfo_parser.add_argument(
		'--secureinfo',
		help='Console\'s SecureInfo_A/B file',
		type=argparse.FileType('rb')
	)
	gen_secinfo_parser.add_argument(
		'--serialnumber',
		help='Console\'s serial number if SecureInfo not given',
		type=SecureInfo.validate_serial
	)
	gen_parser.add_argument(
		'--msed',
		help='Console\'s movable.sed, only add if you need, this will interfere with IVS sync',
		type=argparse.FileType('rb')
	)
	gen_parser.add_argument(
		'--model', '-m',
		help='Console\'s model override',
		type=str
	)
	gen_parser.add_argument(
		'--region', '-r',
		help='Console\'s effective region',
		type=regionaldata.Region.get_region
	)
	gen_parser.add_argument(
		'--country', '-c',
		help='Console\'s effective country',
		type=regionaldata.Country.get_country
	)
	gen_parser.add_argument(
		'--language', '-l',
		help='Console\'s effective language',
		type=regionaldata.Language.get_language
	)
	gen_parser.add_argument(
		'--out', '-o',
		help='Output generated json file, printed to stdout if not given',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	gen_parser.set_defaults(func=_gen_json)

	check_parser = subparsers.add_parser('CheckReg', help='Check registry status')
	check_parser.add_argument(
		'--console', '-C',
		help='Console\'s JSON',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	check_parser.set_defaults(func=_check_register)

	move_parser = subparsers.add_parser('SysTransfer', help='Systransfer account across two consoles (No NNID moved)')
	move_parser.add_argument(
		'--source', '-s',
		help='Console JSON with account to send over',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	move_parser.add_argument(
		'--target', '-t',
		help='Console JSON to receive the account',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	move_parser.set_defaults(func=_move_account)

	move_nnid_parser = subparsers.add_parser('NNIDTransfer', help='Transfer NNID only across two consoles (Use with caution)')
	move_nnid_parser.add_argument(
		'--source', '-s',
		help='Console JSON with account to send over',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	move_nnid_parser.add_argument(
		'--target', '-t',
		help='Console JSON to receive the NNID',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	move_nnid_parser.set_defaults(func=_move_nnid)

	move_check_parser = subparsers.add_parser('LastTransfer', help='Check information about last transfer')
	move_check_parser.add_argument(
		'--console', '-C',
		help='Console\'s JSON',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	move_check_parser.set_defaults(func=_move_check_account)

	givs_parser = subparsers.add_parser('GetIVS', help='Get IVS from servers if existant')
	givs_parser.add_argument(
		'--console', '-C',
		help='Console\'s JSON',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	givs_parser.set_defaults(func=_get_ivs)

	sivs_parser = subparsers.add_parser('SetIVS', help='Set IVS to servers')
	sivs_parser.add_argument(
		'--console', '-C',
		help='Console\'s JSON',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	sivs_parser.set_defaults(func=_set_ivs)

	rivs_parser = subparsers.add_parser('RecoverIVS', help='Attempt recover movable.sed from otp only')
	rivs_parser.add_argument(
		'--otp',
		help='Console\'s encrypted or decrypted otp file',
		required=True,
		type=argparse.FileType('rb')
	)
	rivs_parser.add_argument(
		'--region', '-r',
		help='Console\'s effective region',
		required=True,
		type=regionaldata.Region.get_region
	)
	rivs_parser.add_argument(
		'--country', '-c',
		help='Console\'s effective country',
		required=True,
		type=regionaldata.Country.get_country
	)
	rivs_parser.add_argument(
		'--language', '-l',
		help='Console\'s effective language',
		type=regionaldata.Language.get_language
	)
	rivs_parser.add_argument(
		'--out', '-o',
		help='Output recovered movable.sed',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	rivs_parser.set_defaults(func=_recover_ivs_otp)

	edel_parser = subparsers.add_parser('EShopDelete', help='Delete EShop account')
	edel_parser.add_argument(
		'--console', '-C',
		help='Console\'s JSON',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	edel_parser.set_defaults(func=_del_eshop)

	erchange_parser = subparsers.add_parser('EShopRegionChange', help='Attempt to change EShop account region')
	erchange_parser.add_argument(
		'--console', '-C',
		help='Console\'s JSON',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	erchange_parser.add_argument(
		'--region', '-r',
		help='Console\'s effective region',
		required=True,
		type=regionaldata.Region.get_region_str
	)
	erchange_parser.add_argument(
		'--country', '-c',
		help='Console\'s effective country',
		required=True,
		type=regionaldata.Country.get_country_str
	)
	erchange_parser.add_argument(
		'--language', '-l',
		help='Console\'s effective language',
		type=regionaldata.Language.get_language_str
	)
	erchange_parser.set_defaults(func=_eshop_region_change)

	etiks_parser = subparsers.add_parser('ETickets', help='List owned ETickets')
	etiks_parser.add_argument(
		'--console', '-C',
		help='Console\'s JSON',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	etiks_parser.add_argument(
		'--out', '-o',
		help='Optional output path',
		type=lambda x: pathlib.Path(x).resolve()
	)
	etiks_parser.add_argument(
		'--format', '-f',
		help='Optional output format (text/json)',
		type=str,
		default='text'
	)
	etiks_parser.set_defaults(func=_list_etickets)

	etikdown_parser = subparsers.add_parser('ETicketDownload', help='Download owned ETickets')
	etikdown_parser.add_argument(
		'--console', '-C',
		help='Console\'s JSON',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	etikdown_parser.add_argument(
		'--out', '-o',
		help='Output folder path',
		required=True,
		type=lambda x: pathlib.Path(x).resolve()
	)
	etikdown_parser.add_argument(
		'--decrypt', '-d',
		help='Dump ticket with key decrypted from console-unique layer. Will corrupt if imported with AM',
		action='store_true',
		default=False
	)
	etikdown_select = etikdown_parser.add_mutually_exclusive_group(required=True)
	etikdown_select.add_argument(
		'--all', '-a',
		help='Download all tickets',
		action='store_true',
		default=False
	)
	etikdown_select.add_argument(
		'--ticket-id', '-t',
		help='Ticket ids to download, invalid ones will be skipped',
		type=str,
		nargs='+',
		action='append'
	)
	etikdown_parser.set_defaults(func=_download_etickets)

	# TODO:
	#  - give user power to ignore 404s
	#  - allow downloading contents to folder
	#  - ability to generalize tickets to not be console specific
	etitledown_parser = subparsers.add_parser('ETikTitleDownload', help='Download title of owned ETickets, currently only installable on target console with FBI or similar tool, not Godmode9 or custom-installer.')
	etitledown_parser.add_argument(
		'--console', '-C',
		help='Console\'s JSON',
		required=True,
		type=lambda x: str(pathlib.Path(x).resolve())
	)
	etitledown_parser.add_argument(
		'--out', '-o',
		help='Output folder path',
		required=True,
		type=lambda x: pathlib.Path(x).resolve()
	)
	etitledown_parser.add_argument(
		'--ignore-rights', '-i',
		help='Ignore digital right checks',
		action='store_true',
		default=False
	)
	etitledown_select = etitledown_parser.add_mutually_exclusive_group(required=True)
	etitledown_select.add_argument(
		'--all', '-a',
		help='Download all owned titles',
		action='store_true',
		default=False
	)
	etitledown_select.add_argument(
		'--ticket-id', '-t',
		help='Ticket ids to download, invalid ones will be skipped',
		type=str,
		nargs='+',
		action='append'
	)
	etitledown_parser.set_defaults(func=_download_title_tikid)
	args = parser.parse_args(args)

	if args.boot9:
		keys.register_additional_b9_paths(args.boot9)

	if not keys._load_b9_keys():
		print("There was a problem loading boot9 keys, some operations may fail.")

	args.func(parser, args)
