package main

import (
	"ahe-key-server/fame_key_authority/decentralized"
	"ahe-key-server/fame_key_authority/single"
	"ahe-key-server/maabe_key_authority"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func fameDecService() {
	// get auth id from env
	myI, _ := strconv.Atoi(os.Getenv("NODE"))
	n, _ := strconv.Atoi(os.Getenv("ALL_NODE"))
	mode := os.Getenv("MODE")
	addressesString := os.Getenv("ADDRESSES")
	addresses := strings.Split(addressesString, ",")
	namesString := os.Getenv("NAMES")
	names := strings.Split(namesString, ",")
	port, _ := strconv.Atoi(os.Getenv("AUTH_PORT"))
	cert := os.Getenv("CERT")
	caCert := os.Getenv("CACERT")

	decentralized.InitGlobalValues(n, 1000)
	decentralized.RunFAMEDecAuthority(mode, myI, n, addresses, names, port, cert+".crt",
		cert+".key", caCert+".crt", "fame_key_authority/decentralized/saved_data/"+names[myI]+"_auth.txt")
}

func main() {
	scheme := os.Getenv("SCHEME")

	switch scheme {
	case "maabe":
		maabe_key_authority.MaabeService()
	case "fame":
		single.FameService()
	case "fame_dec":
		fameDecService()
	default:
		fmt.Printf("Please specify SCHEME environment")
	}
}
