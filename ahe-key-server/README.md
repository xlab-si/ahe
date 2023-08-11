# AHE Key Management

Encryption schemes that are based on Attribute Based Encryption (ABE) require a
key management system that provides public keys, and upon request serves
private decryption keys associated with attributes.

This is an implementation of such a key management for ABE schemes FAME and
MAABE. It provides:
- Simple (centralized) key management (single authority) for FAME
- Decentralized key management for FAME that is based on a maliciously secure 
MPC protocol
- Key management with multiple authorities for MAABE scheme

## TLDR
Simply run
```console
docker-compose up
```
to run all provided key management systems on the `localhost` address.


## Run

To run the server first set up the environments that define the properties of
the key management, and then run the Go implemented server. 

### Environment

You have to set the following environment variables:

- `SCHEME` - which scheme will you run, options `maabe`, `fame`, or `fame_dec`.
- `AUTH_ID` - a string name of the authority server.
- `AUTH_PORT` - which port the server will listen on.

#### Decentralized FAME

In the case you are running a single MPC node that is part of a network running
a decentralized FAME protocol you need to define additional values

* `NODE` - integer telling which node are you running
* `ALL_NODE` - number of all MPC nodes
* `ADDRESSES`- addresses of all MPC nodes
* `NAMES` - names of all MPC nodes
* `MODE` - indicates if the service creates new private and public keys or
simpy loads existent, options are `load` and `new`
* `CERT` - location of the certificate you are using
* `CACERT` - location of the certificate of the certificate authority

### Running the service

Simply run
```console
$ go run main.go
```
