# AHE libray

This repository contains implementation of APIs for the AHE library. The source 
of the library is implemented in Go and part of the [GoFE](https://github.com/fentec-project/gofe)
cryptographic library. The code is compiled to a shared object with binding available in
multiple languages. See also the [demos directory](../ahe-demo) for example of how to use the
library.


### Before using the bindings

Before the bindings for any language can be used, one first has to build
the shared library itself. The code can be cross compiled for multiple
architectures and platforms.
The code for the shared library is contained in the
`cgo/` directory. Run
```
cd cgo/
make help
```
to view all available architectures. Then run `make` with the architecture as
the target. After that, `libahe.so` and the accompanying `libahe.h` should be
in the repository's root build directory.

## Supported Languages

* Go
* Python3
* Java
* JS
* C

### Go

The library is natively implemented in as part of [GoFE](https://github.com/fentec-project/gofe),
hence there is no real need for Go language bindings. Using the library is still
described in `Go/README.md`. In `cgo/` directory are functions needed to marshall
objects (ciphertext, public keys, etc.) so that they can be saved/sent and read by
other interfaces.


### Python

The `Python/` directory provides the Python bindings for the library. Instead
of dealing with raw data or arrays of strings, one can use built-in classes.
The main `Ahe` class, provided with a path to the shared library, also loads
the library for you. Consult the `Pyton/README.md` file for more information.

The bindings can also be packaged into a `pip` package and installed directly
into your Python distribution.

### Java

The `Java/` directory provides the Java bindings for the library. It uses and
heavily depends on the
[Java Native Access](https://github.com/java-native-access/jna)
library, which has to be compiled for your architecture before use. A copy of
`jna.jar` is already included, but it might not suffice your needs (though it
is compiled with `android-x86` support). Again, one needs not deal with raw
data or arrays of strings, built-in type classes are provided. The main `Ahe`
class again loads the shared library, but the library has to already be in the
correct place, i.e. in the `<classpath>/<architecture>/` of you project.
Consult the structure of `Java/` and `Java/Makefile` for more details regarding
debugging the compilation process, and the `Java/README.md` file for more
general information.

The intended way to use the bindings is to package them into a JAR file.

### JS

The `Java/` directory provides a mechanism to use the library in JS that can be
run in a browser or a NodeJS code. The approach here is based on using WebAssembly,
which is implemented in `wasm/` directory. Consult `JS/README.md` for more informations.

### C

The `C/` directory does not really contain any bindings as they are not really
needed. Instead, there is a file with reference use of the entire encryption
scheme lifecycle, using the functions from `libahe.so`.

## Tests and examples

Each of the bindings contains tests that can be used to validate the correctness of the
functionalities, as well as offer an example of how to use the library. Additionally,
see the [demos directory](../ahe-demo) and the [Android demo](../ahe-android-app-demo)
for more examples that work with a deployed key manager. One can use
```
make test
```
to run all the tests (assuming that `libahe.so` has been built).
