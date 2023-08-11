# AHE: Java Bindings

## TLDR

To set your `Java` path/version (the parent folder of the distribution's `bin`
directory), set the `JAVA_HOME` environment variable and tell make to use it.
For example, to use the default symlinks on your system, run
```
$ JAVA_HOME=/usr make -e <target>
```
or modify the `Makefile`. This applies to all the following commands.

To build the `ahe.jar` file simply run
```console
$ make jar
```
which also copies the library to the root build directory of this repository.
The archive itself is architecture-agnostic, but `libahe.so` has to be compiled
appropriately.

To build the documentation run
```console
$ make doc
```
and to run the unit test run
```console
$ make test
```

## Details

## Building the JAR file

See above, there is not much more to it. The `make` target simply cleans the
build directory, recompiles all the sources (except the tests) and invokes
`jar`, then copies the archive to the repository's build directory.

## Using the JAR file

Once `ahe.jar` is built and placed in your project appropriately (along with
`jna.jar` and `libahe.so`), using it is as simple as importing the `Ahe` class
and all the types you need. Beware of catching exceptions too, consult the
documentation. Consider the complete lifecycle of the encryption scheme below
(sans the error checking).

```java
import com.arcadian.ahe.Ahe;

import com.arcadian.ahe.type.Maabe;
import com.arcadian.ahe.type.MaabeAuth;
import com.arcadian.ahe.type.MaabePubKey;
import com.arcadian.ahe.type.MaabeSecKey;
import com.arcadian.ahe.type.MaabeKey;
import com.arcadian.ahe.type.MaabeCipher;

// this also loads the shared library
Ahe a = new Ahe();

// initiate a new scheme
Maabe m = a.NewMaabe();
try {
    // construct new authorities
    String id1 = "auth1", id2 = "auth2", id3 = "auth3";
    String[] attribs1 = new String[]{"auth1:at1", "auth1:at2"};
    String[] attribs2 = new String[]{"auth2:at1", "auth2:at2"};
    String[] attribs3 = new String[]{"auth3:at1", "auth3:at2"};
    MaabeAuth auth1 = a.NewMaabeAuth(m, id1, attribs1);
    MaabeAuth auth2 = a.NewMaabeAuth(m, id2, attribs2);
    MaabeAuth auth3 = a.NewMaabeAuth(m, id3, attribs3);

    // collect their pubkeys
    MaabePubKey[] pks = {auth1.Pk, auth2.Pk, auth3.Pk};

    // encrypt a message with a decryption policy
    String msg = "Attack at dawn!";
    String bf = "((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)";
    MaabeCipher ct = a.Encrypt(m, msg, bf, pks);

    // get attribute keys for a user
    String gid = "user1";
    MaabeKey[] keys1 = a.GenAttribKeys(auth1, gid, attribs1);
    MaabeKey[] keys2 = a.GenAttribKeys(auth2, gid, attribs2);
    MaabeKey[] keys3 = a.GenAttribKeys(auth3, gid, attribs3);

    // combine keys
    MaabeKey[] ks1 = {keys1[0], keys2[0], keys3[0]};
    MaabeKey[] ks2 = {keys1[1], keys2[1], keys3[1]};
    MaabeKey[] ks3 = {keys1[0], keys2[1]};
    MaabeKey[] ks4 = {keys1[1], keys2[0]};
    MaabeKey[] ks5 = {keys3[0], keys3[1]};

    String pt1 = a.Decrypt(m, ct, ks1); // returns msg
    String pt2 = a.Decrypt(m, ct, ks2); // returns msg
    String pt3 = a.Decrypt(m, ct, ks3); // returns null
    String pt4 = a.Decrypt(m, ct, ks4); // returns null
    String pt5 = a.Decrypt(m, ct, ks5); // returns msg
} catch (Exception e) {
    System.out.println("Unexpected exception.");
}
```

See the documentation and tests for more details.

## Testing

Again, the `make` target simply recompiles all the source files (with test
files included this time) and runs the tests with `junit-4.13`. The `junit` JAR
file comes with this repository, but feel free to compile/use your own. Do not
forget to adjust the `Makefile` (or adjust the environment).

## Documentation

The documentation is generated automatically using your Java distribution's
`javadoc`, which is what the `make` target uses as well.
