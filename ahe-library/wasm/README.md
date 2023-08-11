# AHE: WASM

This folder provides the code needed to build WASM files for the AHE library. It is meant to provide interface for
AHE in JavaScript.

## Building WASM
Run
````
GOOS=js GOARCH=wasm go build -o he.wasm wasm.go
````
or simply use `make`, which will build `he.wasm` in `../build/`.