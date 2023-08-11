# AHE: C-callable interface

## Compiling the shared library

To compile `libahe.so` in your desired architecture, run
```
make <arch>
```
To get a list of all architectures, run `make` without any targets.  Bare in
mind that compiling for Android requires the Android NDK.  To override the
default locations, update the `Makefile` or adjust the environment.

To run the Go tests, run
```
make test
```

The generated files are put into the repository's build directory (instead of a
local one), where they are ready to be used by the default setting of the
language bindings directories.
