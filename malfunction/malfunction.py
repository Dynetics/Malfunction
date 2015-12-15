# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
# malfunction.py
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
import psutil
import subprocess
import sys
import apsw
import ssdeep
import gradient
import malget
from mallearn import add_sigs

try:
    import progressbar
except ImportError:
    progressbar = None
    print("progressbar not installed, continuing")

# binary_hash always refers to the MD5 hash of a file.
# hash_list always refers to the list of fuzzy hashes of a file.


def argparse_setup():
    """ Set up argparse arguments

    -d debug            -- Details about internal workings
    -u unpack           -- Automatic unpacking of packed binaries
    --leave-db-on-disk  -- Don't load the binary into memory
                        (slower but less costly)
    --add-strong-matches-- Adds the strong matches to the database
                        automatically (use with caution)
    -D database         -- The path to the database the user wants
                        to use, Default='malfunction.db' 
    -a all              -- Compare to all files, not just same type"""

    parser = argparse.ArgumentParser(prog="python3 malfunction.py")
    parser.add_argument("PATH", help="Binary or directory of binaries to run "
                                     "comparisions against")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Prints details about internal objects to the "
                             "terminal")
    parser.add_argument("-u", "--unpack", action="store_true",
                        help="Unpacks packed executables before disassembly. "
                        "Current not implemented.")
    parser.add_argument("--leave-db-on-disk", action="store_true",
                        help="Prevents malfunction from loading the database "
                             "into memory.")
    parser.add_argument("--add-strong-matches", action="store_true",
                        help="This flag adds all the very strongly matched "
                             " binaries into the database.")
    parser.add_argument("-D", "--database", type=str, default='malfunction.db',
                        help="Path to malfunction database. "
                        "Default=malfunction.db in current directory")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Compare to every file in the database instead of "
                             "just files of the same filetype")
    return parser.parse_args()


def prepare_database(leave_db, database=None):
    """ Create the needed tables if they don't exist and
    return the cursor for the database

    leave_db - boolean to prevent loading database to memory
    database - path to the malfunction database file"""

    conn = apsw.Connection(database)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS functions(hash TEXT,binaryID"
                   " TEXT,FOREIGN KEY(binaryID) REFERENCES "
                   "binaries(binaryID))")
    cursor.execute("CREATE TABLE IF NOT EXISTS binaries(binaryID TEXT, "
                   "author TEXT, filenames TEXT, comment TEXT, "
                   "trustlevel TEXT, filetype TEXT);")
    memcon = apsw.Connection(":memory:")

    if (not leave_db):
        with memcon.backup("main", conn, "main") as backup:
            mem = psutil.virtual_memory()
            backup.step(1)
            remaining_pages = backup.remaining

            if mem.free >= remaining_pages * 1024:
                backup.step()
            else:
                print("Not enough free memory to load the database to memory, "
                      "switching to reading from disk...")

        cursor = memcon.cursor()

    return cursor


def get_filetype(path):
    """ Gets the given binary's file type for storage

    Gets the filetype by getting the first 20 characters
    from the 'file' command for a given path"""

    output = str(subprocess.check_output(["file", path]))
    filetype = output.split(':')[1].strip()[0:19].strip()
    return filetype


def process_sigs(cursor, sig_list, bin_list):
    """ Process the function signatures

    Go through every function and compare it to functions in every binary
    Get the highest score per function and add it to a score_list
    cursor - the database cursor
    sig_list - the list of function signatures for analysis
    bin_list - the list of binaries in the current database to compare to"""

    score_list = []

    maxval = 0
    for row in bin_list:
        cursor.execute("SELECT count(hash) FROM functions WHERE binaryid=?", (row[0],))
        maxval += int(cursor.fetchone()[0])
    maxval = maxval*len(sig_list)
    if progressbar:
        widgets = [" ", progressbar.Bar(marker="#"), " ", progressbar.Percentage(), " ", progressbar.ETA()]
        pbar = progressbar.ProgressBar(widgets=widgets,
                           maxval=maxval).start()
    else:
        pbar = None
    i = 0
    for row in bin_list:
        function_score_list = []

        for sig in sig_list:
            highest_score = 0
            cursor.execute("SELECT hash FROM functions WHERE binaryid=?",
                           (row[0], ))
            # h means hash, hash is a keyword in Python
            # so we can't use it

            for h in cursor.fetchall():
                strength = ssdeep.compare(sig, h[0])

                if strength > highest_score:
                    highest_score = strength

                i += 1
                if pbar:
                    pbar.update(i)
                elif i % 10000 == 0 or i == maxval:
                    print("%d / %d Done" % (i, maxval))

            function_score_list.append(highest_score)

        score_list.append(function_score_list)
    if pbar:
        pbar.finish()
    return score_list


def calculate_weights(size_list, debug):
    """ Calculate the score weights based on the size of the functions

    Larger functions are given a heavier weight because its harder to
    match two large functions than it is to match two small functions
    size_list - the sizes of every function in the given binary
    debug - print additional information on binaries"""

    weights = []
    total = sum(size_list)

    for s in size_list:
        weights.append(float(s) / float(total))

    if(debug):
        print("Function weights: ", weights)

    return(weights)


def output(cursor, by_binary_list, whitelist_avg, blacklist_avg):
    """ Print out a report for the output of malfunction

    cursor - database cursor
    by_binary_list - list of strong matching binaries
    whitelist_avg - the whitelist score
    blacklist_avg - the blacklist score"""

    score = whitelist_avg - blacklist_avg

    print("Whitelist Average: " + str(whitelist_avg))
    print("Blacklist Average: " + str(blacklist_avg))
    print("            Score: " + str(score))
    gradient.gradient(score)

    possible_filenames = []
    possible_authors = []
    comments = []
    for binary_id in by_binary_list:
        cursor.execute("SELECT author,filenames,comment FROM "
                       "binaries WHERE binaryID=?", (binary_id, ))
        binary_entry = cursor.fetchone()
        if binary_entry[0] not in possible_authors and binary_entry[0]:
            possible_authors.append(binary_entry[0])
        if binary_entry[1] not in possible_filenames and binary_entry[1]:
            possible_filenames.append(binary_entry[1])
        if binary_entry[2] not in comments and binary_entry[2]:
            comments.append(binary_entry[2])
    if possible_authors:
        print("***Possible Authors of this binary***")
        for author in possible_authors:
            print(author, end=" - ")
    print("\n")
    if possible_filenames:
        print("***Possible Filenames this binary could go by***")
        for filename in possible_filenames:
            print(filename, end=" - ")
    print("\n")
    if comments:
        print("***Comments about similar binaries***")
        for comment in comments:
            print(comment)


def compute_score(cursor, hash_tuple, size_list, filetype, add_strong,
                  compare_all, debug):
    """ Compute a score for the binary based on the
    binaries currently in the database

    cursor - the database cursor
    hash_tuple - (Binary hash, [**function sigs])
    size_list - the list of function lengths
    filetype - the filetype of the binary to learn
    add_strong - boolean to automatically add strongly matched functions to db
    compare_all - comparing to the entire database of just same file type
    debug - output debug information"""

    by_binary_list = []
    if compare_all:
        cursor.execute("SELECT binaryid, trustlevel FROM binaries")
    else:
        cursor.execute("SELECT binaryid, trustlevel FROM binaries "
                       "WHERE filetype=?", (filetype, ))
    bin_list = cursor.fetchall()
    if len(bin_list) == 0:
        print("There is nothing in the database and/or matching that filetype")
        sys.exit(1)
    weights = calculate_weights(size_list, debug)
    blacklist_matches = []
    whitelist_matches = []
    binary_hash = hash_tuple[0]
    sig_list = hash_tuple[1]

    for n, scores in enumerate(process_sigs(cursor, sig_list, bin_list)):
        weighted_scores = []

        for i, s in enumerate(scores):
            if(debug):
                print("Un-weighted: " + str(s))
                print("   Weighted: " + str(s * weights[i]))
            weighted_scores.append(s * weights[i])

        if(debug):
            print("TOTAL: " + str(sum(weighted_scores)))

        total = sum(weighted_scores)
        if total > 25:
            if(bin_list[n][1] == "whitelist"):
                whitelist_matches.append(total)
            elif(bin_list[n][1] == "blacklist"):
                blacklist_matches.append(total)
        if total > 80:
            by_binary_list.append(bin_list[n][0])

    if(len(whitelist_matches) == 0):
        whitelist_matches.append(0)
    if(len(blacklist_matches) == 0):
        blacklist_matches.append(0)

    whitelist_avg = int(sum(whitelist_matches) / len(whitelist_matches))
    blacklist_avg = int(sum(blacklist_matches) / len(blacklist_matches))
    score = whitelist_avg - blacklist_avg

    output(cursor, by_binary_list, whitelist_avg, blacklist_avg)
    # Adds binaries with scores above 80 to the whitelist
    # Adds binaries with scores below -80 to the blacklist
    if score != 100 and score > 80 and add_strong:
        add_sigs(binary_hash, sig_list, "whitelist", filetype)
    elif score != -100 and score < -80 and add_strong:
        add_sigs(binary_hash, sig_list, "blacklist", filetype)


def directory_malfunction(args, cursor):
    """ Runs malfunction on a folder and all files within """

    path = args.PATH
    if not path.endswith("/"):
        path += "/"
    directory = os.listdir(path)
    for file in directory:
        try:
            # Don't follow links so we don't end up in loops.
            if os.path.islink(path + file):
                continue
            # Extend the list if the path points to a directory
            if os.path.isdir(path + file):
                inner_directory = os.listdir(path + file)
                inner_directory = [file+"/"+x for x in inner_directory]
                directory.extend(inner_directory)
                continue
            hash_tuple, size_list = malget.malget(path + file,
                                                  args.unpack)
            filetype = get_filetype(path+file)
            compute_score(cursor, hash_tuple, size_list, filetype,
                          args.add_strong_matches, args.all, args.debug)
            print("-"*30)
        except ValueError:
            print("That file cannot be disassembled")
            print("-"*30)
            continue
        except Exception as err:
            print("There was an error reading that file, are you sure it "
                  "was an executable?\nError Information:")
            print('\t', type(err))
            print('\t', err)
            print("-"*30)
            continue
        except Warning:
            print("That file is already in the database.")
            print("-"*30)
            continue


def main():
    """ Run malfunction, a tool for software analysis

    Usage: python3 malfunction.py <file> """

    args = argparse_setup()

    # TODO: Make files with spaces compatible
    if "\ " in args.PATH or " " in args.PATH:
        print("The radare2 commands we are using for disassembly do not "
              "play nice with spaces in the filename. Rename the file")
        return False

    cursor = prepare_database(args.leave_db_on_disk, args.database)

    path = args.PATH
    dir_check = os.path.isdir(path)

    if dir_check:
        directory_malfunction(args, cursor)
    else:
        try:
            hash_tuple, size_list = malget.malget(path, args.unpack)
            filetype = get_filetype(path)
            compute_score(cursor, hash_tuple, size_list, filetype,
                          args.add_strong_matches, args.all, args.debug)
        except ValueError:
            print("That file cannot be disassembled")
            return False
        except Exception as err:
            print("There was an error reading that file, are you sure it "
                  "was an executable?\nError Information:")
            print('\t', type(err))
            print('\t', err)
            return False
        except Warning:
            print("That file is already in the database.")
            return False
    return True

main()
