# This file is originally a part of pyctr.
#
# Copyright (c) 2017-2021 Ian Burgwin
# This file is licensed under The MIT License (MIT).
# A copy of license as been placed here:

## -- LICENSE --
# The MIT License (MIT)
#
# Copyright (c) 2017-2021 Ian Burgwin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
## -- LICENSE END --

# This is lent from pyctr, from pyctr/util.py @ 854af75, in part, not the full file and some edits.
# Mainly to work independently from pyctr and keep a consistency with pyctr used paths at least.

import typing, os
from sys import platform

__all__ = ['windows', 'macos', 'config_dirs']

windows: bool = platform == 'win32'
macos: bool = platform == 'darwin'

_home = os.path.expanduser('~')
config_dirs: typing.List[str] = [os.path.join(_home, '.3ds'), os.path.join(_home, '3ds')]
if windows:
	config_dirs.insert(0, os.path.join(os.environ.get('APPDATA'), '3ds'))
elif macos:
	config_dirs.insert(0, os.path.join(_home, 'Library', 'Application Support', '3ds'))
