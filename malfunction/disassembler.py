# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
# disassembler.py
#
# Authors: James Brahm, Matthew Rogers, Morgan Wagner, Jeramy Lochner,
# Donte Brock
# -----------------------------------------------------------------------
# Copyright 2015 Dynetics, Inc.
#
# This file is a part of Malfunction
#
# Malfunction is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# Malfunction is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------


import os
import subprocess


def get_data(binary):
    """ Gets the functions from a given file

    Uses radare2 to get function start addresses and length
    Then uses the lengths and starts to snip the functions
    from the original file """

    print("Disassembling " + binary + "...")

    functions = []

    # Open the binary
    f = open(binary, "rb")

    cmd = "r2 " + binary + " -c af -c ?p -c afl -q"
    DEVNULL = open(os.devnull, "w")
    output = subprocess.check_output(cmd, shell=True, stderr=DEVNULL)
    output = output.splitlines()

    pma = int(output.pop(0), 16)
    flist = []
    for line in output:
        flist.append(line.decode("utf-8").split("  "))

    offset = int(flist[0][0], 16) - pma

    # Make a list of functions
    for e in flist:
        size = int(e[1])
        if size > 20:
            f.seek(int(e[0], 16) - offset, 0)
            buf = f.read(size)
            functions.append([buf, size])

    print("Found {0} functions".format(len(functions)))
    return functions
