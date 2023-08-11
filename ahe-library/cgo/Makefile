NDK_ROOT = ${HOME}/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/linux-x86_64/bin

BUILD_DIR=../build

SRC=ahe.go
TESTS=./...
LIB=libahe
OBJ=$(LIB).so
HEAD=$(LIB).h

BENCH_FLAGS= -run=^\# -count 10 -benchtime 10x
BENCH_FILES= GoBench.txt CBench.txt benchmark-report.txt

.PHONY: all default help clean x86 x86_64 arm arm64 test bench

default: help

help:
	@echo "Please specify a target:"
	@echo "  - x86_64"
	@echo "  - arm"
	@echo "  - x86 (for Android)"
	@echo ""
	@echo "  - clean"
	@echo "  - help (this message)"
	@echo "  - test"

clean:
	@rm -fv ${BUILD_DIR}/$(OBJ) ${BUILD_DIR}/$(HEAD) $(BENCH_FILES)

x86:
	@mkdir -p ${BUILD_DIR}
	bash -c 'CC=${NDK_ROOT}/i686-linux-android30-clang CGO_ENABLED=1 GOOS=android GOARCH=386 go build -buildmode=c-shared -o ${BUILD_DIR}/$(OBJ) $(SRC)'

x86_64:
	@mkdir -p ${BUILD_DIR}
	bash -c 'go build -buildmode=c-shared -o ${BUILD_DIR}/$(OBJ) $(SRC)'

armAndroid:
	@mkdir -p ${BUILD_DIR}
	bash -c 'CC=${NDK_ROOT}/armv7a-linux-androideabi30-clang CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 go build -buildmode=c-shared -o ${BUILD_DIR}/$(OBJ) $(SRC)'

armRPI:
	@mkdir -p ${BUILD_DIR}
	bash -c 'CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=7 go build -buildmode=c-shared -o ${BUILD_DIR}/$(OBJ) $(SRC)'

arm64:
	@mkdir -p ${BUILD_DIR}
	bash -c 'CC=${NDK_ROOT}/aarch64-linux-android30-clang CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -buildmode=c-shared -o ${BUILD_DIR}/$(OBJ) $(SRC)'

test:
	go test -v $(TESTS)

bench:
	bash -c 'SEED=123 go test -bench="BenchmarkGo.*" ${BENCH_FLAGS} | tee GoBench.txt'
	bash -c 'SEED=123 go test -bench="BenchmarkC.*" ${BENCH_FLAGS} | tee CBench.txt'
	@sed -i 's/BenchmarkGo/Benchmark/' GoBench.txt
	@sed -i 's/BenchmarkC/Benchmark/' CBench.txt
	benchstat GoBench.txt CBench.txt | tee benchmark-report.txt
	@cp -f benchmark-report.txt ${BUILD_DIR}
