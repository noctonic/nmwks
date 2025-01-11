# nmwks
Download and Upload scripts to a N0120 
Tested with firmware version 23.2.5

```bash
usage: main.py [-h] [-d] [-p] [-u] directory

Tool to upload/download files from a Model N0120 calculator.

positional arguments:
  directory       Path to the local directory used for upload/download.

optional arguments:
  -h, --help      show this help message and exit
  -d, --download  Download userland from the calculator to a local directory.
  -p, --prefs     Read or Modify preference files.
  -u, --upload    Upload userland from a local directory to the calculator.
```
