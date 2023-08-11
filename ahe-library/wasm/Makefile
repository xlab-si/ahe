.PHONY: all default build

default: build

build:
	bash -c 'GOOS=js GOARCH=wasm go build -o ../build/he.wasm wasm.go'
