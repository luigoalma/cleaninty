# cleaninty

Perform operations in ECommerce and some others.

Work-in-progress, use at own discretion.

This tool currently only does 3DS aka CTR, but can be expanded for WiiU in the future too.

This is an early release.

## Important notice

I cannot stress this enough, ***DO NOT SHARE ANY GENERATED JSON OR OTP*** for any console, as **IT ALLOWS ANYONE TO IMPERSONATE YOUR CONSOLE ON NINTENDO'S SERVERS**. If you must share with someone, do it privately and be sure to trust this person. Proceed with caution.

I am not responsible for what other's may do with your console data on Nintendo's servers.

## Installing

Read `Notes` first.

You may run `python3 setup.py install` to install to system or add `--user` to install to user.

You may also install it from PyPI with `pip install cleaninty`.

## Usage

`cleaninty ctr -h` for details.

For the first run, I recommend you to use the [GM9 script `ExtractSystemElements.gm9`](https://raw.githubusercontent.com/luigoalma/cleaninty/master/gm9scripts/ExtractSystemElements.gm9) to extract necessary system elements for keys and certificates on your console, these elements are non-unique. Use extracted files with `SetupConstants`, check `cleaninty ctr SetupConstants -h` for help. You'll still need the AES HW Constant C in hexadecimal string as part of this command's arguments, which you'll have to find out yourself.

## Notes

Tested in python 3.7 to 3.11 in Linux. You may have trouble installing `pycurl` on windows, need to have libcurl binaries and MSVC to install it.

## TODO

- [x] Proper setup.py
- [ ] More proper logging
- [ ] More SOAPs
- [ ] NUS connect simulation
- [ ] Others I forgot

## License

The Unlicense license, check `LICENSE.md` for details.

Any files that were taken from any other project have their individual licenses added to them as a header.
* `cleaninty/ctr/_env.py` is under MIT License, [from pyctr/util.py](https://github.com/ihaveamac/pyctr/blob/854af753baec34e6b2313730b8d81c6ea777e3eb/pyctr/util.py)
