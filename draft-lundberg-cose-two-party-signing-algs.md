---
stand_alone: true
ipr: trust200902

title: "Split signing algorithms for COSE"
abbrev: "Split signing algorithms for COSE"
lang: en
category: std

docname: draft-lundberg-cose-two-party-signing-algs-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "COSE"
keyword:
 - COSE
 - Signing
 - Algorithms
 - Split algorithms
 - Split signing

venue:
  group: "COSE"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  github: "YubicoLabs/cose-two-party-signing-algs-rfc"


author:
- role: editor
  fullname: Emil Lundberg
  organization: Yubico
  street: Gävlegatan 22
  city: Stockholm
  country: SE
  email: emil@emlun.se

- fullname: Michael B. Jones
  ins: M.B. Jones
  organization: Self-Issued Consulting
  email: michael_b_jones@hotmail.com
  uri: https://self-issued.info/
  country: United States

normative:
  I-D.bradleylundberg-ARKG: I-D.draft-bradleylundberg-cfrg-arkg
  I-D.jose-fully-spec-algs: I-D.draft-ietf-jose-fully-specified-algorithms
  I-D.pairing-curves: I-D.draft-irtf-cfrg-pairing-friendly-curves
  IANA.COSE:
    target: https://www.iana.org/assignments/cose/
    title: CBOR Object Signing and Encryption (COSE)
    author:
    - org: IANA
  RFC2119:
  RFC8017:
  RFC8032:
  RFC8174:
  RFC8235:
  RFC8610:
  RFC9052:
  SEC1:
    target: https://www.secg.org/sec1-v2.pdf
    author:
    - org: Certicom Research
    date: May 2009
    title: "SEC 1: Elliptic Curve Cryptography"

informative:
  FIPS-204:
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
    title: Module-Lattice-Based Digital Signature Standard
    author:
    - org: National Institute of Standards and Technology
    date: August 2024
  FIPS-186-5:
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
    title: Digital Signature Standard (DSS)
    author:
    - org: National Institute of Standards and Technology
    date: February 2023
  I-D.COSE-Hash-Envelope: I-D.draft-ietf-cose-hash-envelope
  RFC9380:
  SECDSA:
    target: https://eprint.iacr.org/2021/910
    title: 'SECDSA: Mobile signing and authentication under classical "sole control"'
    author:
    - fullname: Eric Verheul
    date: July 2021


--- abstract

This specification defines COSE algorithm identifiers used when one signing operation
is split between two cooperating parties.
When performing split signing,
the first party typically hashes the data to be signed
and the second party signs the hashed data computed by the first party.
This can be useful when communication with the party holding the signing private key
occurs over a limited-bandwidth channel, such as NFC or Bluetooth Low Energy (BLE),
in which it is infeasible to send the complete set of data to be signed.
The resulting signatures are identical in structure to those computed by a single party,
and can be verified using the same verification algorithm
without additional steps to preprocess the signed data.

--- middle

{:emlun: source="Emil"}

# Introduction

CBOR Object Signing and Encryption (COSE) [RFC9052]
algorithm identifiers are used to specify the cryptographic operations
used to create cryptographic data structures,
but do not record internal details of how the cryptography was performed,
since those details are typically irrelevant for the recipient.
The algorithm identifiers defined by this specification facilitate
splitting a signing operation between two cooperating parties,
by specifying the division of responsibilities between the two parties.
The resulting signature can be verified by the same verification algorithm
as if it had been created by a single party,
so this division of responsibilities is an implementation detail of the signer.
Verifiers therefore do not use these split algorithm identifiers,
and instead use the corresponding non-split algorithm identifier
which identifies the same verification algorithm as the split algorithm identifier would.

A primary use case for this is splitting a signature operation between a software application
and a discrete hardware security module (HSM) holding the private key.
In particular, since the data link between them may have limited bandwidth,
it may not be practical to send the entire original message to the HSM.
Instead, since most signature algorithms begin with digesting the message
into a fixed-length intermediate input, this initial digest can be computed by the software application
while the HSM computes the rest of the signature algorithm on the digest.

Since different signature algorithms digest the message in different ways
and at different stages of the algorithm,
there is no one generally-applicable way to define such a division point
for every possible signature algorithm.
Therefore, this specification defines algorithm identifiers encoding,
for a specific set of signature algorithms,
which steps of the signature algorithm are performed by the _digester_ (e.g., software application)
and which are performed by the _signer_ (e.g., HSM).
In general, the _signer_ holds exclusive control of the signing private key.

Note that these algorithm identifiers do not define new "pre-hashed" variants of the base signature algorithm,
nor an intermediate "hash envelope" data structure, such as that defined in [I-D.COSE-Hash-Envelope].
Rather, these identifiers correspond to existing signature algorithms
that would typically be executed by a single party,
but split into two stages.
The resulting signatures are identical to those computed by a single party,
and can be verified using the same verification algorithms
without additional special steps to process the signed data.

However some signature algorithms,
such as PureEdDSA [RFC8032],
cannot be split in this way and therefore cannot be assigned split signing algorithm identifiers.
However, if such a signature algorithm defines a "pre-hashed" variant,
such as Ed25519ph [RFC8032],
that "pre-hashed" algorithm can also be assigned a split signing algorithm identifier,
enabling the hashing step to be performed by the _digester_
and the signing step to be executed by the _signer_.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

# Split Signing Algorithms

This section defines divisions of signing algorithm steps between a _digester_ and a _signer_
in a split signing protocol,
and assigns algorithm identifiers to these algorithm divisions.
The _digester_ performs the first part of the split algorithm and does not have access to the signing private key,
while the _signer_ performs the second part of the split algorithm and has access to the signing private key.
For signing algorithms that format the message to insert domain separation tags,
as described in {{Section 2.2.5 of RFC9380}},
this message formatting is also performed by the _signer_.

The algorithm identifiers defined in this specification
MAY appear in COSE structures used internally between the _digester_ and the _signer_ in a split signing protocol,
but SHOULD NOT appear in COSE structures consumed by signature verifiers.
COSE structures consumed by signature verifiers
SHOULD instead use the corresponding conventional algorithm identifiers for the verification algorithm.
These are listed in the "Verification algorithm" column in the tables defining split signing algorithm identifiers.


## ECDSA {#ecdsa-split}

ECDSA [FIPS-186-5] split signing uses the following division between the _digester_ and the _signer_
of the steps of the ECDSA signature generation algorithm [FIPS-186-5]:

- The signing procedure is defined in Section 6.4.1 of [FIPS-186-5].
- The _digester_ performs Step 1 of the signing procedure - hashing the message, producing the value _H_.
- The message input to the _signer_ is the value _H_ defined in the signing procedure.
- The _signer_ resumes the signing procedure from Step 2.

The following algorithm identifiers are defined:

| Name         | COSE Value | Verification algorithm | Description |
| ------------ | ---------- | ---------------------- | ----------- |
| ESP256-split | TBD        | ESP256                 | ESP256 [I-D.jose-fully-spec-algs] split signing as defined here
| ESP384-split | TBD        | ESP384                 | ESP384 [I-D.jose-fully-spec-algs] split signing as defined here
| ESP512-split | TBD        | ESP512                 | ESP512 [I-D.jose-fully-spec-algs] split signing as defined here


Note: This is distinct from the similarly named Split-ECDSA (SECDSA) [SECDSA],
although SECDSA can be implemented using this split procedure as a component.


## HashEdDSA {#eddsa-split}

Split HashEdDSA [RFC8032] uses the following division between the _digester_ and the _signer_
of the steps of the HashEdDSA signing algorithm [RFC8032]:

- HashEdDSA is a combination of the EdDSA signing procedure and the PureEdDSA signing procedure.
  The EdDSA signing procedure is defined in the first paragraph of {{Section 3.3 of RFC8032}}.
  The PureEdDSA signing procedure is defined in the second paragraph of {{Section 3.3 of RFC8032}}.
- The _digester_ computes the value `PH(M)` defined in the EdDSA signing procedure.
- The message input to the _signer_ is the value `PH(M)` defined in the EdDSA signing procedure.
  This value is represented as `M` in the PureEdDSA signing procedure.
- The _signer_ executes the PureEdDSA signing procedure,
  where the value denoted `M` in the PureEdDSA signing procedure
  takes the value denoted `PH(M)` in the EdDSA signing procedure.

PureEdDSA [RFC8032] cannot be divided in this way
since such a division would require that the _digester_ has access to the private key.

The following algorithm identifiers are defined:

| Name            | COSE Value | Verification algorithm | Description |
| --------------- | ---------- | ---------------------- | ----------- |
| Ed25519ph-split | TBD        | Ed25519ph              | Ed25519ph [I-D.jose-fully-spec-algs] split signing as defined here (NOTE: Ed25519ph not yet registered) |
| Ed448ph-split   | TBD        | Ed448ph                | Ed448ph [I-D.jose-fully-spec-algs] split signing as defined here (NOTE: Ed448ph not yet registered) |


## Split-BBS

THIS SECTION IS AN EARLY DRAFT AND NOT READY FOR ADOPTION OR STANDARDIZATION.
FOR PROTOTYPING PURPOSES ONLY.

This is a signing procedure for BBS device binding, based on the "Split-BBS" protocol
proposed in "Device Binding for BBS Signatures" by Cordian Daniluk and Anja Lehmann.

THIS SIGNING PROCEDURE HAS NOT BEEN THOROUGHLY ANALYZED FOR SECURITY.
USE FOR TESTING PURPOSES ONLY.

The signing inputs are:

- `crv`: A pairing-friendly elliptic curve
  with prime order subgroup generator `G` of (prime) order `N`
  and curve scalars encoded in `Clen` octets.
- `H`: A cryptographic hash function outputting digests of length `Hlen` octets.
- `a`: The signing private key, an integer mod `N`.
- `c_host`: A `Hlen`-length octet string containing the challenge hash to be signed.
- `t2prime`: A curve point to add to the nonce point before hashing.
  If not present, `t2prime` is taken as the point at infinity
  (the identity element of the curve group).

The signature consists of an integer `s` and two byte strings `c` and `n`
computed by the following protocol
based on a Schnorr Non-Interactive Zero Knowledge proof [RFC8235]:

 1. Verify that `t2prime` is a valid point on `crv`.
 2. Sample `n` as `Hlen` uniformly random bytes.
 3. Sample `v` uniformly random in \[1, `N`-1\]
 4. `t_dsk = [v] x G`
 5. `t2 = t2prime + t_dsk`
 6. `c = H(n || ECP2OS(t2) || c_host)`
 7. `s = v - a * c (mod N)`
 8. Return `I2OSP(s, 32) || c || n`

`ECP2OS` is the "Elliptic-Curve-Point-to-Octet-String" procedure
defined in section 2.3.3 of [SEC1], without point compression.
`I2OSP` is defined in {{Section 4.1 of RFC8017}}
(also `I2OSP(x, 32)` is equivalent to the
"Field-Element-to-Octet-String" procedure defined in [SEC1]).

The following algorithm identifiers are defined:

| Name           | COSE Value               | Base algorithm | Description |
| ---------------| ------------------------ | -------------- | ----------- |
| SplitBBS-BS256 | TBD (placeholder -65602) | (None)         | Split-BBS as defined here with SHA256 as `H`, 32 as `Hlen`, BLS12-381 [I-D.pairing-curves] as `crv` and 32 as `Clen` |

The following COSE curve identifiers are defined:

| Name      | COSE Value               | Description |
| --------- | ------------------------ | ----------- |
| BLS12_381 | TBD (placeholder -65601) | The curve BLS12-381 [I-D.pairing-curves] |

The `t2prime` signing input may be represented as attribute `-10`
of `COSE_Sign_Args` (see {{cose-sign-args}}).
The value is a COSE_Key encoding `t2prime` as a public key on `crv`.

The following CDDL example represents a `COSE_Sign_Args` structure
with a `t2prime` input to use during signing with SplitBBS-BS256:

~~~cddl
{
  3: -65602,   ; alg: SplitBBS-BS256 (placeholder value)

  -10: {       ; t2prime argument to Split-BBS signing procedure
    1: 2,        ; kty: EC2
    -1: -65601,  ; crv: BLS12_381
                 ; x coordinate of t2prime
    -2: h'19c902dfc093fe8165c98543dae09a3d4a9006dfb5ba1e6e46b7495f9384e4c26d1af74302ff95bc922d4b1649ed9630',
                 ; y coordinate of t2prime
    -3: h'0ef6b57c2fdb550b33287728daed69637201eb53294cc82c304c3e3937fd1c7346e6da79d242c25ffa728130316130a5',
  },
}
~~~


# COSE Signing Arguments {#cose-sign-args}

While many signature algorithms take the private key and data to be signed as the only two parameters,
some signature algorithms have additional parameters that must also be set.
For example,
to sign using a key derived by ARKG [I-D.bradleylundberg-ARKG],
two additional arguments `kh` and `info` are needed in `ARKG-Derive-Private-Key` to derive the signing private key.

While such additional arguments are simple to provide to the API of the signing procedure in a single-party context,
in a split signing context these additional arguments also need to be conveyed from the _digester_ to the _signer_.
For this purpose, we define a new COSE structure `COSE_Sign_Args` for "COSE signing arguments".
This enables defining a unified, algorithm-agnostic protocol between the _digester_ and the _signer_,
rather than requiring a distinct protocol for each signature algorithm for the sake of conveying algorithm-specific parameters.

`COSE_Sign_Args` is built on a CBOR map.
The set of common parameters that can appear in a `COSE_Sign_Args`
can be found in the IANA "COSE Signing Arguments Common Parameters" registry (TODO).
Additional parameters defined for specific signing algorithms
can be found in the IANA "COSE Signing Arguments Algorithm Parameters" registry (TODO).

The CDDL grammar describing `COSE_Sign_Args`, using the CDDL fragment defined in {{Section 1.5 of RFC9052}}, is:

~~~cddl
COSE_Sign_Args = {
    3 ^ => tstr / int,  ; alg
    * label => values,
}
~~~


## COSE Signing Arguments Common Parameters {#cose-sign-args-common}

This document defines a set of common parameters for a COSE Signing Arguments object.
{{tbl-cose-sign-args-common}} provides a summary of the parameters defined in this section.

{: #tbl-cose-sign-args-common title="Common parameters of the COSE_Sign_Args structure."}
| Name | Label | CBOR Type  | Value Registry  | Description |
| ---- | ----- | ---------- | --------------- | ----------- |
| alg  | 3     | tstr / int | COSE Algorithms | Signing algorithm to use |

- alg: This parameter identifies the signing algorithm the additional arguments apply to.
  The signer MUST verify that this algorithm matches any key usage restrictions set on the key to be used.
  If the algorithms do not match, then the signature operation MUST be aborted with an error.

Definitions of COSE algorithms MAY define additional algorithm-specific parameters for `COSE_Sign_Args`.

The following CDDL example conveys additional arguments for signing data
using the ESP256-split algorithm (see {{ecdsa-split}})
and a key derived using `ARKG-P256` [I-D.bradleylundberg-ARKG]:

~~~cddl
{
  3: -65539,   ; alg: ESP256-split with ARKG-P256 (placeholder value)

               ; ARKG-P256 key handle
               ; (HMAC-SHA-256-128 followed by
                  SEC1 uncompressed ECDH public key)
  -1: h'27987995f184a44cfa548d104b0a461d
        0487fc739dbcdabc293ac5469221da91b220e04c681074ec4692a76ffacb9043de
          c2847ea9060fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361',

               ; info argument to ARKG-Derive-Private-Key
  -2: 'ARKG-P256.test vectors',
}
~~~


# IANA Considerations {#IANA}

## COSE Algorithms Registrations {#cose-alg-reg}

This section registers the following values in the IANA "COSE Algorithms" registry [IANA.COSE]:

- Name: ESP256-split
  - Value: TBD (Requested Assignment -300)
  - Description: ESP256 [I-D.jose-fully-spec-algs] split signing
  - Capabilities: \[kty\]
  - Change Controller: IETF
  - Reference: {{ecdsa-split}} of this specification
  - Recommended: Yes

- Name: ESP384-split
  - Value: TBD (Requested Assignment -301)
  - Description: ESP384 [I-D.jose-fully-spec-algs] split signing
  - Capabilities: \[kty\]
  - Change Controller: IETF
  - Reference: {{ecdsa-split}} of this specification
  - Recommended: Yes

- Name: ESP512-split
  - Value: TBD (Requested Assignment -302)
  - Description: ESP512 [I-D.jose-fully-spec-algs] split signing
  - Capabilities: \[kty\]
  - Change Controller: IETF
  - Reference: {{ecdsa-split}} of this specification
  - Recommended: Yes

- Name: Ed25519ph-split
  - Value: TBD (Requested Assignment -303)
  - Description: Ed25519ph [I-D.jose-fully-spec-algs] split signing
  - Capabilities: \[kty\]
  - Change Controller: IETF
  - Reference: {{eddsa-split}} of this specification
  - Recommended: Yes

- Name: Ed448ph-split
  - Value: TBD (Requested Assignment -304)
  - Description: Ed448ph [I-D.jose-fully-spec-algs] split signing
  - Capabilities: \[kty\]
  - Change Controller: IETF
  - Reference: {{eddsa-split}} of this specification
  - Recommended: Yes


## COSE Signing Arguments Common Parameters Registry

TODO

## COSE Signing Arguments Algorithm Parameters Registry

TODO


--- back

# Document History
{: numbered="false"}

-02

* Renamed document from "COSE Algorithms for Two-Party Signing" to "Split signing algorithms for COSE"
  and updated introduction and terminology accordingly.
* Dropped definitions for HashML-DSA, as split variants of ML-DSA are being actively discussed in other IETF groups.
* Changed "Base algorithm" heading in definition tables to "Verification algorithm".
* Remodeled COSE_Key_Ref as COSE_Sign_Args.
  * Dropped definitions of reference types for COSE Key Types registry.

-01

* Added IANA registration requests for algorithms defined.
* Updated references and other editorial tweaks.

-00

* Initial individual draft
