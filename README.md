# AHE encryption system ![build and test](https://github.com/xlab-si/ahe/actions/workflows/build-and-test.yml/badge.svg)


## Description

AHE is an encryption system developed by [XLAB](https://xlab.si/) in [Arcadian-IoT](https://www.arcadian-iot.eu/)
project to harden and simplify
the encryption mechanism in a setting with big amounts of data and many participants, such
as an IoT setting (hence the name AHE as Arcadian Hardened Encryption). It is based on the
Attribute-Based Encryption (ABE) and decentralization paradigms.

Traditionally, the data in transit or at rest is secured by encrypting it with
symmetric or public key encryption. The latter can be cumbersome, especially if the encrypted data
is not only secured for 1-to-1 transition but also needed by many decryptors. Quickly,
complicated access policies are required, which need to be enforced by design.

A naive solution is to introduce a central component to the system, that ether collects all the
data and distributes it the correct way or a key management component that distributes it correctly
private/public keys to clients according to the access policies. In the former case, the centralized
component with access to all the data presents an obvious cybersecurity thread, while the latter
case the solution results in a vast amount of keys in the system and multiple duplications of encrypted
data (that are needed by various receivers).

The AHE system is built on the Attribute-Based Encryption (ABE) mechanism. It allows a distribution of
private keys according to so-called _attributes_ (roles) while enabling data encryption with
access policies specified by the encryptors themselves. This gives the producers of data direct
control of who can decrypt their data, which is strongly guaranteed by the encryption scheme itself,
i.e., no additional trust is needed beyond cryptographic assumptions. In addition, this gradually
reduces the number of cryptographic keys and ciphertexts in the system since it allows encrypting
data once for multiple (groups) of receivers.

The AHE system includes an easy-to-deploy ABE key management system. Since any key management system
introduces a need for trust, an additional effort was put into reducing the needed trust in the system
by *decentralizing* the key management component. Hence, we enable the deployment of the key management
system as a centralized authority, multi-authority system, or as a Multi-Party Computation (MPC) system
proven secure against malicious players (nodes). In the latter setting, the key management system
can be trusted as long as at least one of the MPC nodes is not compromised.

<p align="center">
<img src="ahe-demo/ahe.png" width=60%/>
</p>
<p align="center">
<em>Example of a use of AHE.</em>
</p>

## Implementation

The repository is divided into the following directories:
* [ahe-library](ahe-library/): It includes the implementation of an AHE library that can be used in multiple types
  of devices, platforms, and programming languages. In particular, the library can be compiled (using Go) for the chosen
  device and used (with provided bindings) in Go, Java, Python, C, or JavaScript. The library enables the devices
  to encrypt and decrypt with ABE, receive public/private keys from key management and provides a unified way for
  (un) marshaling (changing to bytes and back) ciphertexts, keys, and other structures.
* [ahe-key-management](ahe-key-server/): It provides an implementation of various key management needed to use
  ABE library in practice. The key management can be deployed as a centralized authority, a multi-authority system,
  or as a Multi-Party Computation (MPC) system. It is implemented in Go and fully Dockerized, hence easy to deploy.
* [ahe-demo](ahe-demo/) and [ahe-android-app-demo](ahe-android-app-demo/): It includes various demos of how
  the `ahe-library` can be used in all of its interfaces and how to in interact with a key-management system.


## Technical details

### Implementation
To provide the functionality of ABE on multiple platforms and in multiple interface languages while staying high
on efficiency and usability, we chose the following
approach.
* We implemented the heart of the library in Go language. To be precise, we implemented it as part of the Functional
  encryption library [GoFE](https://github.com/fentec-project/gofe). Go then allows compiling the code to shared objects
  for many architectures. The shared object can be used by many programming languages where the efficiency of Go (in this
  case, comparable to C implementation) is preserved.
* We provided bindings in Java and Python to use the library with the (object-oriented) paradigms of specific languages.
* Since the Go library is compiled into a shared object, it provides a direct interface to C.
* Additionally, the library can also be compiled into a Web Assembly (WASM) file. WASM is a binary instruction format
  for a stack-based virtual machine, hence designed as a portable compilation target. For example, it can be used by
  JavaScrypt directly in a browser (on an arbitrary device). We use WASM for the interface to the library that can be used
  by JavaScrypt (or NodeJS).

### ABE schemes

We provide an implementation of two ABE schemes:
* A Ciphertext Policy (CP) ABE scheme named FAME by _Agrawal, Chase_ ([paper](https://eprint.iacr.org/2017/807.pdf))
  allowing encrypting a message based on a boolean expression defining a policy of which attributes are needed for the
  decryption.
* A Multi-Authority (MA) ciphertext policy (CP) ABE scheme by
  _Lewko, Waters_ ([paper](https://eprint.iacr.org/2010/351.pdf)) based on a boolean expression defining a policy
  in which attributes are needed for decryption. This scheme is decentralized - the attributes can be spread across
  multiple different authorities.

We refer to the schemes as FAME and MAABE, respectively. We advise to see the [ahe-demo](ahe-demo/) repository to
see how to use either of the schemes.

### Key management

Every ABE scheme needs a key management system. The key management system generates a public key (or multiple
public keys in the case of multiple authorities) that every client can use to encrypt their data according to a
desired policy (policy is independent of the public key). Furthermore, clients having various roles in the system
can request a private key corresponding to their attributes/roles. This allows them to decrypt precisely the
data meant for them. We provide a Dockerized implementation of key authorities that can be easily deployed.

The two implemented schemes have a different approaches to key management:
##### FAME scheme
The FAME scheme was developed as a fast CP-ABE scheme with a centralized key manager that provides
a single (short, constant size) public key that allows every client to encrypt its data with arbitrary policy. This is
known as a large universe scheme in the ABE world, implying that there could be arbitrarily many attributes (hence also
clients) associated with roles in the system while not affecting efficiency. Furthermore, the key manager can
provide clients with private decryption keys associated with their attributes.

Since having a centralized authority that has access to all the decryption keys presents a security risk, we put
extra effort into decentralizing this component so that the trust in it is spread among multiple nodes. We based
the decentralization on Multi-Party Computation (MPC) technology. In particular, we provide the following:
* An implementation of [SPDZ](https://eprint.iacr.org/2011/535.pdf) protocol, by Damgard, Pastro, Smart, and Zakarias,
  for public and private ABE key generation. SPDZ is an efficient, maliciously secure MPC protocol that can
  guarantee its security as long as there is at least one MPC node in the system that is not malicious. In our case,
  this means that we can deploy, instead of one single key management authority, a system of _n_ computation nodes that
  can securely communicate with each other and provide the same functionality. To compromise such a system and gain power
  over it, a malicious actor would need to compromise all the _n_ nodes. This extends the trust in the system.
* The efficiency of SPDZ is based on the fact that the protocol can be split into 2 phases, usually named the offline and
  online phases. The offline phase is non-specific to the computation that needs to be done in the online phase; hence
  it can be done in advance. In the online phase (in our case, when a client requests a private key), the key management
  system computes the key for the specific ABE attributes. To have the online phase as efficient as possible, we
  set up the parameters (particularly certain prime numbers) of the SPDZ scheme to match the parameters of the ABE scheme.
* We implement the offline phase based on the [Mauer](https://crypto.ethz.ch/publications/files/Maurer02b.pdf)
  The maliciously secure protocol assumes an honest majority of the computation nodes. The choice is based
  on the fact that the order of the finite field of the so-called multiplication triples and shares needs to be a
  specific and rather big prime (that is, the order of the pairing group used in the ABE schemes). The protocol is
  fast for a small _n_ while for a larger setting a different approach should replace it.

#### MAABE scheme
As the name suggests, the Multi-Authority ABE scheme allows deploying of multiple key managing authorities for key
distribution. Each key managing authority shares its own public key associated with (in advance defined) attributes.
This allows a client to encrypt data with policies that include attributes coming from different key authorities.
For example, a client can enforce a decryption policy with attributes coming from all the key authorities. Hence
the trust in the key management can be decentralized. In comparison with the FAME scheme, this allows more flexibility
and a simpler key management process (compared to the MPC system for FAME). In fact, also the encryption and decryption
processes are more efficient. Nevertheless, this comes at a price: All the attributes in the system need to be known in
advance and directly affect the size of the public keys. There also needs to be a clear distinction between which attributes are
provided by which authorities to avoid collisions. Lastly, if a ciphertext is encrypted with a very long policy
(including attributes of many authorities), the process is accordingly more complex.

In both cases, the key management entities are deployed as a web service that can be accessed by GET and PUST requests.
We use self-signed certificates to ensure private communication with or among key authorities.


#### Application-specific Authorization
Important: What the implemented key management does not provide is the authorization protocol defining which clients can
request which private keys (attributes). This is purely application specific and needs to be defined by a use case.
For example, in the [Arcadian-IoT](https://www.arcadian-iot.eu/) the clients used a specific Arcadian-IoT
multi-factor authentication to prove to the server that they can request a private key corresponding to the attribute
with the same name as their UUID in the system.


### Signatures:

Securing the data by just encrypting can be problematic and open the possibility for a man-in-the-middle attack,
where a malicious entity could replace encrypted data with a different one. To prevent this attack, the encrypted
payloads should be signed. We provide a unified signing functionality for all the library's interfaces. Additionally,
the key managing has an optional functionality to sign the public (verification) keys. Concretely, a client
that wishes to use the signature functionality can generate private/public signature keys and send the public key to a
key management authority. The key managing authority provides a certificate proving the ownership of the public key.

## Licence:

The code is released under the MIT licence.
