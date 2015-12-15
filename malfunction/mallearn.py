# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
# mallearn.py
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
import os
import re
import sqlite3
import sys
import malget
import subprocess

# binary_hash always refers to the MD5 hash of a file.
# hash_list always refers to the list of fuzzy hashes of a file.


def argparse_setup():
    """ Set up argparse arguments

     -a author           -- Suspected author of binary
     -f filenames        -- Potential filenames that the binary came from
     -c comments         -- Comments on the binaryy
     -o overwrite        -- Overwrite existing instances in the database
     -u unpack           -- Automatic unpacking of executables 
     -s sigsOnly         -- Skip disassembly and add sig file to database
     -D database         -- Change the path of the database"""

    parser = argparse.ArgumentParser(prog="python3 mal-learn")
    parser.add_argument("-a", "--author", type=str, default="unknown",
                        help="The Author of the given binary")
    parser.add_argument("PATH", help="Path to the target binary or binaries")
    parser.add_argument("-f", "--filenames", type=str, default="unknown",
                        help="The name of the file that the Binary came from")
    parser.add_argument("-u", "--unpack", action="store_true",
                        help="Unpacks packed executables before disassembly. "
                        "Currently not implemented.")
    parser.add_argument("-c", "--comment", type=str, default="",
                        help="A comment to add to the database")
    parser.add_argument("trustlevel", type=str,
                        choices=["blacklist", "whitelist"],
                        help="The classification of the binary, Ex. WhiteList,"
                             " BlackList.")
    parser.add_argument("-o", "--overwrite", action="store_true",
                        help="Overwrites an older instance of a binary "
                             "in the database with the given one")
    parser.add_argument("-s", "--sigsOnly", action="store_true",
                        help="Skips the disassembly and just learns the "
                        "signatures")
    parser.add_argument("-D", "--database", type=str, default='malfunction.db',
                        help="Path to malfunction database. "
                        "Default=malfunction.db in current directory")
    args = parser.parse_args()
    return args


def check_overlap(cursor, binary):
    """ Determine if the given binary is already in the database """

    cursor.execute("SELECT binaryID FROM binaries")
    rows = cursor.fetchall()
    for row in rows:
        if (row[0] == binary):
            return True
    return False


def check_format(binary_hash, hash_list):
    """ Make sure the functions and binary signatures are
    in the correct format """

    if not (check_binary_hash(binary_hash)):
        print("The md5 hash at the top of the signatures provided was not "
              "in the proper format. Use malget to ensure it is properly "
              "formatted.")
        sys.exit()
    for function_hash in hash_list:
        if not (check_ssdeep(function_hash)):
            print("The ssdeep hash {0} was not in the proper format. Use "
                  "malget to ensure the file is in the proper "
                  "format".format(function_hash))
            sys.exit()
    print("All hashes match the proper format")
    return True


def check_binary_hash(binary_hash):
    """ Verify that the binary hash is an md5 hash """

    var = re.findall(r"([a-fA-F\d]{32})", binary_hash)
    if str(var) != ("['"+binary_hash+"']"):
        return False
    return True


def check_ssdeep(function_hash):
    """ Verify all the function hashes are ssdeep hashes """

    var = re.findall(r"([0-9]+:[a-zA-Z\d\/+]+:[a-zA-z\d\/+]+)", function_hash)
    if str(var) != ("['"+function_hash+"']"):
        return False
    return True


def get_filetype(path):
    """ Get the file type from the given binary

    Gotten by the getting the first 20 character of the 'file' command"""

    output = str(subprocess.check_output(["file", path]))
    filetype = output.split(':')[1].strip()[0:19].strip()
    return filetype


def mallearn(args, binary_hash, hash_list, filetype, trustlevel="blacklist"):
    """ Runs mal-learn which inserts the binary and its function hashes into
    their respective tables """

    author = "unknown"
    filenames = "unknown"
    comment = ""
    database = "malfunction.db"

    if args:
        author = args.author
        filenames = args.filenames
        comment = args.comment
        trustlevel = args.trustlevel
        overwrite = args.overwrite
        database = args.database
    else:
        print("Something went wrong with the argument parser.")
        sys.exit(1)

    # Verify that the given database has the correct tables and if not,
    # create them
    con = sqlite3.connect(database)
    cursor = con.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS binaries(binaryID TEXT,"
                   "author TEXT,filenames TEXT,comment TEXT,trustlevel TEXT,"
                   "filetype TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS functions(hash TEXT,binaryID"
                   " TEXT,FOREIGN KEY(binaryID) REFERENCES "
                   "binaries(binaryID))")
    con.commit()

    # Check for overlaps and if --overwrite has been used
    if (check_overlap(cursor, binary_hash) and overwrite is False):
        raise Warning("Warning: given binary matches one in the database,"
                      " use --overwrite if you wish to overwrite this entry\n")
    if(overwrite):
        cursor.execute("SELECT * FROM binaries")
        cursor.execute("DELETE FROM binaries WHERE binaryID=?", (binary_hash,))
        con.commit()

    # Add the binary hash and the functions to their respective tables
    cursor.execute("INSERT INTO binaries VALUES(?,?,?,?,?,?)",
                   (binary_hash, author, filenames,
                    comment, trustlevel, filetype))
    for hash in hash_list:
        cursor.execute("INSERT INTO functions VALUES(?,?)", (hash, binary_hash))
    con.commit()
    print("=>\tAdded to database")


def add_sigs(binary_hash, hash_list, trustlevel, filetype):
    """ Add signatures to database from signature file rather than binary """

    hash_list = [x.strip() for x in hash_list]
    print("=>\tAdding to database...")
    mallearn(None, binary_hash, hash_list, filetype, trustlevel=trustlevel)


def directory_learn(args):
    """ Learns an entire directory and its inner directories to db

    Runs through a folder and extends all of its folders, and
    adds them all to Malfunction database """

    path = args.PATH
    if not path.endswith("/"):
        path += "/"
    directory_path = path
    directory = os.listdir(path)
    for file in directory:
        try:
            path = directory_path + file
            # Check for links so we don't accidently get an infinite loop.
            if os.path.islink(path):
                continue
            # Extend the list of files by one layer.
            if os.path.isdir(path):
                inner_directory = os.listdir(path)
                inner_directory = [file+"/"+x for x in inner_directory]
                directory.extend(inner_directory)
                continue
            # Learn the sigs if path isn't to a folder or link.
            if args.sigsOnly is True:
                f = open(path, "r")
                binary_hash = f.readline().strip()
                hash_list = [x.strip() for x in f]
                f.close()
                check_format(binary_hash, hash_list)
            else:
                hash_tuple, sizes = malget.malget(path, args.unpack)
                binary_hash = hash_tuple[0]
                hash_list = [x.strip() for x in hash_tuple[1]]
            print("Adding {0} to database...".format(path))
            args.filenames = directory_path+file
            filetype = get_filetype(path)
            mallearn(args, binary_hash, hash_list, filetype)
            print("-"*30)
        except ValueError:
            print("That file cannot be disassembled")
            print("-"*30)
            continue
        except Warning:
            print("That file is already in the database, use the -o flag to "
                  "overwrite")
            print("-"*30)
            continue
        except Exception as err:
            print("There was an error reading that file, are you sure it "
                  "was an executable?\nError Information:")
            print('\t', type(err))
            print('\t', err)
            print("-"*30)
            continue


def main():
    """ Learns the given binary to the database. Used if you know if a binary is
    good or bad (Notepad vs. a known malware)

    Usage:
       python3 mallearn malware.exe blacklist -a 'Bad Guy' -c 'Some malware'
       python3 mallearn notepad.exe whitelist -a 'Microsoft' -D 'test.db'"""

    args = argparse_setup()

    # Check if path is a directory, if so, run mal-get and mal-learn
    # for the entire directory
    is_directory = os.path.isdir(args.PATH)
    if is_directory:
        directory_learn(args)
        return True
    else:
        try:
            path = args.PATH
            # This makes sure if sigsOnly is used that it follows
            # the binary_hash, hash_list format
            if args.sigsOnly is True:
                f = open(path, "r")
                binary_hash = f.readline().strip()
                hash_list = [x.strip() for x in f]
                f.close()
                check_format(binary_hash, hash_list)
            else:
                    hash_tuple, sizes = malget.malget(path, args.unpack)
                    binary_hash = hash_tuple[0]
                    hash_list = [x.strip() for x in hash_tuple[1]]
            if args.filenames == 'unknown':
                args.filenames = path
            filetype = get_filetype(path)
            mallearn(args, binary_hash, hash_list, filetype)
            return True
        except ValueError:
            print("That file cannot be disassembled")
            return False
        except Warning:
            print("That file is already in the database, use the -o flag to "
                  "overwrite")
            return False
        except Exception as err:
            print("There was an error reading that file, are you sure it "
                  "was an executable?\nError Information:")
            print('\t', type(err))
            print('\t', err)
            return False

    return True


if __name__ == "__main__":
    main()
