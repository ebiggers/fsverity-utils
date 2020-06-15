# fsverity-utils release notes

## Version 1.1

* Split the file measurement computation and signing functionality
  of the `fsverity` program into a library `libfsverity`.  See
  `README.md` and `Makefile` for more details.

* Improved the Makefile.

* Added some tests.  They can be run using `make check`.  Also added
  `scripts/run-tests.sh` which does more extensive prerelease tests.

* Lots of cleanups and other small improvements.

## Version 1.0

* First official release of fsverity-utils.
