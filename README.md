# cleaninty

Perform operations in ECommerce and some others.

Work-in-progress, use at own discretion.

This tool currently only does 3DS aka CTR, but can be expanded for WiiU in the future too.

This is an early release.

## Important notice

I cannot stress this enough, ***DO NOT SHARE ANY GENERATED JSON OR OTP*** for any console, as **IT ALLOWS ANYONE TO IMPERSONATE YOUR CONSOLE ON NINTENDO'S SERVERS**. If you must share with someone, do it privately and be sure to trust this person. Proceed with caution.

I am not responsible for what other's may do with your console data on Nintendo's servers.

## Usage

Currently there's no setup.py for this. You may run it by having the terminal's current directory in the cloned repository folder. You may run `python3 -m pip -r requirements.txt` to install requirements, but read `Notes` first.

`python3 -m cleaninty ctr -h` for details.

I recommend you to run the GM9 script `ExtractSystemElements.gm9` to extract necessary system elements for keys and certificates on your console. Use extracted files with `SetupConstants`, check `python3 -m cleaninty ctr SetupConstants -h` for help.

## Notes

Tested in python 3.10 in Linux. You may have trouble installing `pycurl` on windows, need to have libcurl binaries and MSVC to install it.

## TODO

- [ ] Proper setup.py
- [ ] More proper logging
- [ ] More SOAPs
- [ ] NUS connect simulation
- [ ] Others I forgot

## License

The Unlicense license, check `LICENSE.md` for details.

Any files that were taken from any other project have their individual licenses added to them as a header.
* `cleaninty/ctr/_env.py` is under MIT License, [from pyctr/util.py](https://github.com/ihaveamac/pyctr/blob/854af753baec34e6b2313730b8d81c6ea777e3eb/pyctr/util.py)
