module demo

go 1.19

require (
	ahe-key-server v0.0.0-00010101000000-000000000000
	cgo v0.0.0-00010101000000-000000000000
	github.com/fentec-project/gofe v0.0.0-20220829150550-ccc7482d20ef
)

require (
	github.com/fentec-project/bn256 v0.0.0-20190726093940-0d0fc8bfeed0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/xlab-si/ahe v0.0.0-20230811141416-0413eb2e7cdb // indirect
	golang.org/x/crypto v0.0.0-20211115234514-b4de73f9ece8 // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
)

replace cgo => ./../../ahe-library/cgo

replace ahe-key-server => ./../../ahe-key-server/
