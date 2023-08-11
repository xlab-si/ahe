CC=gcc
CFLAGS= -Wall -Wextra --pedantic -g -O0

BUILD_DIR=../build

PROGRAM=ctest
LIBS= $(BUILD_DIR)/libahe.so

.PHONY: all default clean compile test

default: compile

clean:
	@rm -fv $(BUILD_DIR)/$(PROGRAM)

compile:
	$(CC) $(CFLAGS) ahe_test.c -o $(BUILD_DIR)/$(PROGRAM) $(LIBS)

test:
	@$(BUILD_DIR)/$(PROGRAM) && echo "Passed C test" || echo "Failed C test"
