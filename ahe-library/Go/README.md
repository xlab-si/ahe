# AHE: Go Bindings

## TLDR

Since the underlying library is currently already written in Go, it is
recommended to skip the middleman shared library and simply use the Go package
`github.com/fentec-project/gofe/abe` and its `ma-abe.go` and `fame.go` file. The entire
lifecycle of the encryption scheme is detailed in its test file
`ma-abe_test.go` and `ma-abe_test.go`.

To see a demo of how functionalities are ment to work check `ahe-demo/demo_fame.go`. 

However, if you still desire to work with lists of strings and something
similar to bindings (which might be easier if one is working with encoded and
marshalled data), the `../cgo/ahe.go` file provides a lot of convenience
functions. Their use is described in the test file `../cgo/ahe_test.go`, the
following is a higher level overview.

## Details

### Analogous functions

If you are familiar with `libahe.so`'s functions that accept and return
C-types, i.e. functions named `Ahe_maabe_<function-name>`, then `../cgo/ahe.go`
provides identical functions that accept and return `[]string` Go slices
instead of `char **`. Their naming convention is simply
`Go_Ahe_maabe_<function-name>`.

### Serialization functions

If you prefer to work directly with the underlying Go types, but are stuck with
encoded and marshalled data in lists of strings, `../cgo/ahe.go` provides
numerous convenience functions that serialize and deserialize the data. Their
naming convention follows `<Type>ToRaw` and `<Type>FromRaw`, respectively.

### Type conversion

If you really insist on using the `libahe.so` shared library, and need help
only with converting serialized data in the form of lists of strings to and
from C-types, the `../cgo/ahe.go` file has you covered as well. It provides two
functions `GoSliceToCStringArray` and `CStringArrayToGoSlice` that correctly
transfer between Go and C string arrays, but keep in mind that you are in
charge of freeing your own memory. For convenience, functions that convert
between Go and C `int`, and between Go `string` and C `char *` are also
provided.

### Loading the library

If you *really* insist on loading the actual shared library and using its
exported functions, you can simply load it with cgo. For example

```go
package usinglibahe

// #cgo LDFLAGS: -lahe
//
// #include "libahe.h"
import "C"

func main() {
    maabeC = C.Ahe_maabe_NewMAABE()
    // and so on
}
```

Note that `libahe.h` and `libahe.so` should be somewhere where your compiler
and linker can find them.

Using type conversion functions provided by `../cgo/ahe.go` is recommended,
unless you enjoy working with C-types in Go (in which case you should probably
be using C anyway).
