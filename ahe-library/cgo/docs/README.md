# Documentation for libahe.so

This file contains a compact but detailed overview of `libahe.so`, mainly how
it handles data.

## Serialization of Go types

The `libahe.so` library at its core wraps Go code from
`github.com/fentec-project/gofe/abe`. To avoid unnecessary complexity of the
exposed C-callable interface, each Go type is represented by a string array,
i.e. `char **`, in the following ways.

### Maabe

The `Maabe` type represents global parameters of the scheme. Its Go signature
is

```go
type MAABE struct {
    P   *big.Int
    G1  *bn256.G1
    G2  *bn256.G2
    Gt  *bn256.GT
}
```

It is serialized by:

* stringifying `P`,
* marshaling and Base64 encoding `G1`, `G2`, `GT`,

and assembling them in a string list as

```
[P, G1, G2, GT]
```

The length of the resulting list must always equal 4.

### MaabePubKey

The `MaabePubKey` type represents an authority's public key. Its Go signature
is

```go
type MAABEPubKey struct {
    Attribs     []string
    EggToAlpha  map[string]*bn256.GT
    GToY        map[string]*bn256.G2
}
```

It is serialized by:

* keeping the attributes as strings,
* marshaling and Base64 encoding all `GT` and `G2` type values,

and assembling them into a string list in groups of 3 as

```
[Attribs[0], EggToAlpha[Attribs[0]], GToY[Attribs[0]], Attribs[1], EggToAlpha[Attribs[1]], GToY[Attribs[1]],...]
```

The length of the resulting list must always be a multiple of 3.

### MaabeAuth

The `MaabeAuth` type represents an authority, together with its public and
secret keys. Its Go signature is

```go
// secret key helper type
type MAABESecKey struct {
    Attribs []string
    Alpha   map[string]*big.Int
    Y       map[string]*big.Int
}

type MAABEAuth struct {
    ID      string
    Maabe   *MAABE
    Pk      *MAABEPubKey
    Sk      *MAABESecKey
}
```

It is serialized by:

* keeping the ID as a string,
* serializing `Maabe` data as in the `Maabe` type,
* keeping the attributes in `MaabePubKey` and `MaabeSecKey` as strings,
* serializing `MaabePubKey` data as in the `MaabePubKey` type,
* stringifying `*big.Int` type data in `MaabeSecKey`,

and assembling them into a string list by first giving the ID, then appending
the serialized `Maabe` data, then appending 5-tuples of key data as

```
[ID, P, G1, G2, GT, Attribs[0], EggToAlpha[Attribs[0]], GToY[Attribs[0]], Alpha[Attribs[0]], Y[Attribs[0]],...]
```

The length of the resulting list must always be a multiple of 5 greater than 5.

### Matrix

The `Matrix` type is simply a 2D array of ` *big.Int` values. It should not be
used directly, as it is only used implicitly by the `MaabeCipher` type to store
the decryption policy. It is represented by a single string of the following
space-separated values:

* integer-to-string converted number of rows,
* integer-to-string converted number of columns,
* stringified values of elements of rows.

For example:

```
| a b |
| c d | --> "3 2 a b c d e f"
| e f |
```

### MaabeCipher

The `MaabeCipher` type represents a ciphertext. Its Go signature is

```go
type MAABECipher struct {
    C0      *bn256.GT
    C1x     map[string]*bn256.GT // keys are attributes
    C2x     map[string]*bn256.G2 // keys are attributes
    C3x     map[string]*bn256.G2 // keys are attributes
    Msp     *MSP // contains P (*big.Int), Mat (Matrix), RowToAttrib (ordered list of strings, none of which contain spaces)
    SymEnc  []byte
    Iv      []byte
}
```

It is serialized by:

* Base64 encoding `SymEnc` and `Iv`,
* setting `MSP.P` to the string `"0"` as it is never used,
* serializing `MSP.Mat` as in the `Matrix` type into a single string,
* joining the list `MSP.RowToAttrib` by spaces into a single string,
* marshaling and Base64 encoding all `GT` and `G2` type values,

and assembling them into a string list as

```
[SymEnc, Iv, MSP.P, MSP.Mat, MSP.RowToAttrib, C0, attrib0, C1x[attrib0], C2x[attrib0], C3x[attrib0],...]
```

The length of the resulting list must always be 6 plus a multiple of 4 greater than 0.

### MaabeKey

The `MaabeKey` type represents an attribute decryption key. Its Go signature is

```go
type MAABEKey struct {
    Gid     string
    Attrib  string
    Key     *bn256.G1
}
```

It is serialized by:

* keeping the `Gid` and the `Attrib` as strings,
* marshaling and Base64 encoding `Key`,

and assembling them into a string list as

```
[Gid, Attrib, Key]
```

The length of the resulting list must always equal 3.

Since `MaabeKey` variables are most commonly used as lists, one represents the
`[]MaabeKey` type by simply concatenating the string lists for single keys
together into a longer list whose length must always be a multiple of 3.

## The core function interface

Core functions are those pertaining to basic cryptographic functionality, such
as key generation, encryption, and decryption. Most of the core functions
simply take in serialized representations of the necessary data, deserialize
them into Go types, then call the corresponding Go functions, and return the
serialized result. To learn how to use the functions, consult the `ahe_test.go`
file, concretely `TestMaabeGoC` and `TestMaabeC`, which test the entire
life cycle of the encryption scheme.

## The JSON function interface

Apart from providing a C-callable interface to the GoFE encryption library,
`libahe.so` provides a unified way to marshal data into JSON. Currently, the
supported types are `MaabePubKey`, `MaabeCipher`, and `MaabeKey`, which should
suffice for regular use. All bindings for `libahe.so` should use this functions
to marshal and unmarshal JSON data instead of implementing their own.

It is important to note that all data is serialized in exactly the same way as
during type serialization, in fact the same functions are used under the hood.

### MaabePubKey

The `MaabePubKey` type is transformed into the following JSON structure

```json
{
    "pubkey": {
        "attributes": ["attrib0", "attrib1",...],
        "eggToAlpha": {
            "attrib0": "serialized EggToAlpha[attrib0]",
            "attrib1": "serialized EggToAlpha[attrib1]",
            ...
        },
        "gToY": {
            "attrib0": "serialized GToY[attrib0]",
            "attrib1": "serialized GToY[attrib1]",
            ...
        }
    }
}
```

### MaabeCipher

The `MaabeCipher` type is transformed into the following JSON structure

```json
{
    "cipher": {
        "symEnc": "serialized SymEnc",
        "iv": "serialized Iv",
        "msp-p": "serialized MSP.P",
        "msp-mat": "serialized MSP.Mat",
        "msp-rta": "serialized MSP.RowToAttrib",
        "c0": "serialized C0",
        "c1": {
            "attrib0": "serialized C1x[attrib0]",
            "attrib1": "serialized C1x[attrib1]",
            ...
        }
        "c2": {
            "attrib0": "serialized C2x[attrib0]",
            "attrib1": "serialized C2x[attrib1]",
            ...
        }
        "c3": {
            "attrib0": "serialized C3x[attrib0]",
            "attrib1": "serialized C3x[attrib1]",
            ...
        }
    }
}
```

### MaabeKey list

The `[]MaabeKey` type is transformed into the following JSON structure

```json
{
    "keys": [
        {
            "gid": "string gid",
            "attribute": "string attrib0",
            "key": "serialized Key for attrib0"
        },
        {
            "gid": "string gid",
            "attribute": "string attrib1",
            "key": "serialized Key for attrib1"
        },
        ...
    ]
}
```
