module he_wasm

go 1.19

require (
	ahe-key-server v0.0.0-00010101000000-000000000000
	cgo v0.0.0-00010101000000-000000000000
	github.com/fentec-project/gofe v0.0.0-20220829150550-ccc7482d20ef
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fentec-project/bn256 v0.0.0-20190726093940-0d0fc8bfeed0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/xlab-si/ahe v0.0.0-20230811141416-0413eb2e7cdb // indirect
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d // indirect
	golang.org/x/sys v0.0.0-20220319134239-a9b59b0215f8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cgo => ./../cgo

replace ahe-key-server => ./../../ahe-key-server/
