PIP=python3 -m pip

BUILD=python3 -m build
BUILD_FLAGS= 
TEST=python3 -m unittest
TEST_FLAGS= -v

.PHONY: all default pre pre-build build test pre-doc doc clean

default: pre-build build pre-doc doc

pre-build:
	@$(PIP) install --upgrade build

pre-doc:
	@$(PIP) install --upgrade sphinx

pre: pre-build pre-doc

build:
	@$(BUILD) $(BUILD_FLAGS)

test:
	@$(TEST) $(TEST_FLAGS)
	rm signing_private_key.txt

doc:
	@mkdir -p doc/source/_static
	@$(MAKE) -s -C doc/ clean html

clean:
	@$(MAKE) -s -C doc/ clean
	@echo Removing dist files...
	@rm -rvf dist/ src/ahe_bindings.egg-info/
	@echo Cleaning caches...
	@rm -rvf test/__pycache__/ src/ahe_bindings/__pycache__/
