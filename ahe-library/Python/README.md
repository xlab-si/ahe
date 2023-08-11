# AHE: Python Bindings

## TLDR

To install the build system and build the package run
```console
$ make pre-build build
```
and likewise for building the documentation
```console
$ make pre-doc doc
```
Simply running `make` builds both.

Testing is done by running
```console
$ make test
```

## Details

### Building the package

It is generally recommended to use virtual environments, so create one and activate it
```console
$ python3 -m venv .venv
$ source .venv/bin/activate
```
Then install the dependencies and the build system and build the packages
```console
(.venv) $ python3 -m pip install build
(.venv) $ python3 -m build
```
which builds the `wheel` package and puts it into `dist/`.

### Installing the package

Once in possession of the `.whl` file, installing it is as simple as
```console
$ python3 -m pip install <package>.whl
```

There are currently no plans to upload built packages to any online
repositories that `pip` has access to. To use it in your project, you can
either build it yourself (see above) or simply copy the
`src/ahe-bindings/ahe_*.py` somewhere in your project tree.

### Using the package

Once installed, import the package and use its most important `Ahe` class to
access the functions in `libahe.so`. All native types are hidden in Python
classes. Below is the complete lifecycle of the encryption scheme. See also
[this demo](https://gitlab.com/arcadian_iot/hardened_encryption/-/tree/main/ahe-demo)
for more details.

There are two encryption schemes implemented, FAME that supports a large universe of
attributes, and MAABE that has multiple authorities delegating keys. Preferably use
FAME in ARCADIAN-IoT.



#### FAME interface

```python
from ahe-bindings
import Ahe

# initiate and set scheme to FAME
g = Ahe("/path/to/libahe.so")
g.SetScheme("fame")

# a key managing authority generates master keys
pk, sk = g.NewFameGenerateMasterKeys()

# initiate an entity by generating its signing key (in the eSIM)
# and verification key
verification_key = g.GenerateSigningKeys()

# encrypt a message with a decryption policy
msg = "Attack at dawn!"
bf = "((at1 AND at2) OR at3"
enc = g.Encryp(msg, bf, pk)

# encrypt another message with a different policy
msg2 = "Bring chocolate!"
bf2 = "((at1 OR at3) AND at4"
enc2 = g.Encryp(msg2, bf2, pk)

# join both ciphertexts in a message and sign it with RoT signature
enc_signed = g.Sign([enc, enc2])

# get attribute keys for the entity
attrib_keys = g.GenAttribKeys(sk, ["at1", "at2"])

# verify the authenticity of the ciphertext and decrypt it
pt1 = g.VerifyAndDecrypt(enc_signed, attrib_keys, verification_key, pk)
# returns [msg, None] since the entity posseses only attributes
# that satisfy policy bf and not bf2
```


#### MAABE interface

```python
from ahe-bindings
import Ahe

# initiate
g = Ahe("/path/to/libahe.so")
g.SetScheme("maabe")

# construct new authorities
auth1 = g.NewMaabeAuth("auth1", ["auth1:at1", "auth1:at2"])
auth2 = g.NewMaabeAuth("auth2", ["auth2:at1", "auth2:at2"])
auth3 = g.NewMaabeAuth("auth3", ["auth3:at1", "auth3:at2"])

# initiate an entity by generating its signing key (in the eSIM)
# and verification key
verification_key = g.GenerateSigningKeys()

# an entity collects the pubkeys of the authorities
pks = [auth1.Pk, auth2.Pk, auth3.Pk]

# encrypt a message with a decryption policy
msg = "Attack at dawn!"
bf = "((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)"
enc = g.Encrypt(msg, bf, pks)

# sign a message with RoT signature
enc_signed = g.Sign([enc])

# get attribute keys for a user
gid = "gid1"
keys1 = g.GenAttribKeys(auth1, gid, ["auth1:at1", "auth1:at2"])
keys2 = g.GenAttribKeys(auth2, gid, ["auth2:at1", "auth2:at2"])
keys3 = g.GenAttribKeys(auth3, gid, ["auth3:at1", "auth3:at2"])

# combine keys
ks1 = [keys1[0], keys2[0], keys3[0]]
ks2 = [keys1[1], keys2[1], keys3[1]]
ks3 = [keys1[0], keys2[1]]
ks4 = [keys1[1], keys2[0]]
ks5 = [keys3[0], keys3[1]]

# verify the authenticity of the ciphertext and decrypt it
pt1 = g.VerifyAndDecrypt(enc_signed, ks1, verification_key)  # returns [msg]
pt2 = g.VerifyAndDecrypt(enc_signed, ks2, verification_key)  # returns [msg]
pt3 = g.VerifyAndDecrypt(enc_signed, ks3, verification_key)  # fails with None
pt4 = g.VerifyAndDecrypt(enc_signed, ks4, verification_key)  # fails with None
pt5 = g.VerifyAndDecrypt(enc_signed, ks5, verification_key)  # returns [msg]
```

A single instance will most likely be using only certain parts of the above
lifecycle. To see how raw data should be fed into type classes (or which
classes even exist), see the documentation.

### Documentation

To build the documentation you need to first install `sphinx` by
```console
(.venv) $ python3 -m pip install sphinx
```

After that go to `doc/` and run
```console
(.venv) $ make clean doc
```

### Testing

To run all test, simply run
```console
$ python3 -m unittest -v
```

