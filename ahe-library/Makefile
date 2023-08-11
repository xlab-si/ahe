BUILD_DIR=build

.PHONY: all default build test

default:
	@echo "Please specify a target."

build:
	@$(MAKE) -s -C cgo/ x86_64
	@$(MAKE) -s -C wasm/ build
	@$(MAKE) -s -C Java/ jar

test:
	@$(MAKE) -s -C cgo/ test
	@$(MAKE) -s -C C/ test
	@$(MAKE) -s -C Python/ test
	@$(MAKE) -s -C JS/ test
	@$(MAKE) -s -C Java/ test
	@$(MAKE) -s -C Java/ test
