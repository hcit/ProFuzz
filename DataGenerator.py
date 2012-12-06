#!/usr/bin/env python

# This file is part of ProFuzz.

# ProFuzz is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ProFuzz is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with ProFuzz.  If not, see <http://www.gnu.org/licenses/>.

# Authors: Dmitrijs Solovjovs, Tobias Leitenmaier, Daniel Mayer


import random

#random number
def randNumber(length=0 ):

    if length == 0:    
        rNum = random.randrange(1,30000)
    else:
        rNum = random.randrange(1, length)
    return rNum


#random string
def randString(length=0):
    rstr = ''
    if length == 0:
        for i in range(0,randNumber()):
            rNum = random.randrange(1,256)
            rstr += "%c"%(rNum)
    else:
        for i in range(0,length):
            rNum = random.randrange(1,256)
            rstr += "%c"%(rNum)      
    return rstr
