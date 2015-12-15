# Malfunction

Malfunction is a set of tools for cataloging and comparing malware at a function level. Uses Radare2 internally for finding function locations. Written in Python 3.
Currently only works on Linux based systems.

Jeramy Lochner and Matthew Rogers gave a presentation on Malfunction for DerbyCon on 9/25/2015 in Louisville, KY.
http://www.irongeek.com/i.php?page=videos/derbycon5/stable08-malfunctions-functions-automated-static-malware-analysis-using-function-level-signatures-matthew-rogers-jeramy-lochner

## Installation

Manual Installation (Example work for Ubuntu 14.04 64bit)
```bash
Install prerequisites 
$ apt-get install git build-essential libffi-dev python3 python3-dev python3-pip automake autoconf libtool
$ BUILD_LIB=1 pip3 install ssdeep
$ pip3 install psutil
Clone this repository
Install the latest version of libsqlite3
$ wget http://launchpadlibrarian.net/207018503/libsqlite3-0_3.8.10.2-1_amd64.deb
$ dpkg -i libsqlite3-0_3.8.10.2-1_amd64.deb
Install the latest version of libsqlite3-dev
$ wget http://launchpadlibrarian.net/207018504/libsqlite3-dev_3.8.10.2-1_amd64.deb
$ dpkg -i libsqlite3-dev_3.8.10.2-1_amd64.deb
Install the latest version of apsw
$ wget https://github.com/rogerbinns/apsw/releases/download/3.8.10.1-r1/apsw-3.8.10.1-r1.zip
$ unzip apsw-3.8.10.1-r1.zip
$ cd apsw-3.8.10.1-r1.zip
$ python3 setup.py install
Install the latest version of progress-python3 (OPTIONAL)
$ git clone https://github.com/coagulant/progressbar-python3.git
$ cd progressbar-python3
$ python3 setup.py install
Install the latest version of radare2
$ git clone https://github.com/radare/radare2.git
$ cd radare2
$ ./configure
$ make
$ make install
```

## General Usage

Using mallearn to add a piece of malware to the database, then use malfucntion to compare another program with it.

```bash
$ python3 mallearn.py malware.exe blacklist
$ python3 malfuntion.py possiblymalware.exe
```

## Documentation

### mal-get
mal-get 'gets' the function-level fuzzy hashes from a given binary and is usually used in conjunction with mal-learn or malfunction  

```bash
$ python3 malget.py [FILE] -o output.txt
```

### mal-learn

mal-learn is used for known malware, or things you want to white-list and learns them to the database  

```bash
$ python3 mallearn.py malware.exe blacklist -a 'Bad Guy' -c 'Evil piece of malware'  
$ python3 mallearn.py notepad.exe whitelist -a 'Microsoft Corporation' -c "Notepad.exe" -p 4
```

### Malfunction

Malfunction generates reports on a unknown binary, based on the signatures in the database.  

```bash
$ python3 malfunction.py [FILE]
```

## Authors

A bunch of high school/college interns at Dynetics.

- Matthew Rogers
- Jeramy Lochner
- James Brahm
- Morgan Wagner
- Donte Brock
