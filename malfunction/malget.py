# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
# malget.py
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

import argparse
import hashlib
import shutil
import subprocess
import ssdeep
import disassembler


def argparse_setup():
    """ Set up argparse arguments 
    -o output       -- output file for hashes
    -u unpack       -- automatic unpacking"""

    parser = argparse.ArgumentParser(prog="python3 malget.py")
    parser.add_argument("PATH", help="Path to the binary or binaries")
    parser.add_argument("-o", "--output", type=str, help="output file for "
                        "signatures")
    parser.add_argument("-u", "--unpack", action="store_true",
                        help="Unpacks packed executables before disassembly. "
                        "Currently not implemented.")
    return parser.parse_args()


def check_packed(filename, unpack):
    """ Linux only solution for checking if a file is unpacked"""

    if not shutil.which("grep"):
        print("Cannot check if binary is packed")
        return False

    package_breadcrumbs = ["UPX", "aspack", "NSP", "NTKrnl",
                           "PEC2", "PECompact2", "Thermida", "aPa2Wa"]
    print("Determining if {0} is packed".format(filename), end="...")
    for packer in package_breadcrumbs:
        returncode = subprocess.call(["grep", packer, filename])
        if returncode == 0:
            print("That file is most likely packed by {0}".format(packer))
            return True
    print("That file is likely not packed by common packers")
    return False


def get_binary_hash(filename):
    """ Get the md5 hash of the file to put at the top of the document """

    blocksize = 65536
    hasher = hashlib.md5()
    with open(filename, "rb") as afile:
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
    return hasher.hexdigest()


def get_hash_tuple(functions, filename):
    """ Creates the binary tuple for use in Malfunction and Mallearn

    Results in the form: (Binary Hash, [**ssdeep hashes])"""

    function_hashes = []
    binary_hash = get_binary_hash(filename)
    for function in functions:
        function_hashes.append(ssdeep.hash(function))
    return (binary_hash, function_hashes)


def malget(filename, unpack):
    """ Callable function to run malget, which gets function
    signatures for malfunction

    filename - the name of the file to get signatures for
    unpack - boolean for automatic unpacking """

    packed = check_packed(filename, unpack)
    if packed:
        print("That file is packed and may not disassemble correctly")
    function_lists = disassembler.get_data(filename)
    functions, sizes = zip(*function_lists)
    # Passing the sizes up to Malfunction, since Malget won't use
    # them for anything if called by Mallearn
    return get_hash_tuple(functions, filename), sizes


def main():
    """ Determines the file type then outputs the binary md5 hash
     and the function fuzzy hashes

     Usage:
        python malget.py [FILE] """

    args = argparse_setup()

    output_file = "malgetOutput.txt"
    if args.output:
        output_file = args.output
    binary_tuple, sizes = malget(args.PATH, args.unpack)
    with open(output_file, "w") as f:
        f.write(binary_tuple[0]+"\n")
        for item in binary_tuple[1]:
            f.write(item + "\n")
    print("Output to file {0}".format(output_file))

if __name__ == "__main__":
    main()
