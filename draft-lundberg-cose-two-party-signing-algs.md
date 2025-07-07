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
  I-D.COSE-ML-DSA: I-D.draft-ietf-cose-dilithium
  I-D.jose-fully-spec-algs: I-D.draft-ietf-jose-fully-specified-algorithms
  IANA.COSE:
    target: https://www.iana.org/assignments/cose/
    title: CBOR Object Signing and Encryption (COSE)
    author:
    - org: IANA
  RFC2119:
  RFC8032:
  RFC8174:
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
and can be verified using the same verification procedure
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
The resulting signature can be verified by the same verification procedure
as if it had been created by a single party,
so this division of responsibilities is an implementation detail of the signer.
Verifiers therefore do not use these split algorithm identifiers,
and instead use the corresponding non-split algorithm identifier
which identifies the same verification procedure as the split algorithm identifier would.

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
and can be verified using the same verification procedures
without additional special steps to process the signed data.

However some signature algorithms,
for example, PureEdDSA [RFC8032] and ML-DSA [FIPS-204],
cannot be split in this way and therefore cannot be assigned split signing algorithm identifiers.
However, if such a signature algorithm defines a "pre-hashed" variant,
such as Ed25519ph [RFC8032] or HashML-DSA [FIPS-204],
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

The algorithm identifiers defined in this specification MUST NOT appear in COSE structures
other than COSE_Key_Ref (see {{cose-key-refs}}).
They are meant only for coordination between the _digester_ and the _signer_ in a split signing protocol.
Representations of the keys used and the resulting signatures
MUST use the corresponding conventional algorithm identifiers instead.
These are listed in the "Base algorithm" column in the tables defining split signing algorithm identifiers.


## ECDSA {#ecdsa-split}

ECDSA [FIPS-186-5] split signing uses the following division between the _digester_ and the _signer_
of the steps of the ECDSA signature generation algorithm [FIPS-186-5]:

- The signing procedure is defined in Section 6.4.1 of [FIPS-186-5].
- The _digester_ performs Step 1 of the signing procedure - hashing the message, producing the value _H_.
- The message input to the _signer_ is the value _H_ defined in the signing procedure.
- The _signer_ resumes the signing procedure from Step 2.

The following algorithm identifiers are defined:

| Name         | COSE Value | Base algorithm | Description |
| ------------ | ---------- | -------------- | ----------- |
| ESP256-split | TBD        | ESP256         | ESP256 [I-D.jose-fully-spec-algs] split signing as defined here
| ESP384-split | TBD        | ESP384         | ESP384 [I-D.jose-fully-spec-algs] split signing as defined here
| ESP512-split | TBD        | ESP512         | ESP512 [I-D.jose-fully-spec-algs] split signing as defined here


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

| Name            | COSE Value | Base algorithm | Description |
| --------------- | ---------- | -------------- | ----------- |
| Ed25519ph-split | TBD        | Ed25519ph      | Ed25519ph [I-D.jose-fully-spec-algs] split signing as defined here (NOTE: Ed25519ph not yet registered) |
| Ed448ph-split   | TBD        | Ed448ph        | Ed448ph [I-D.jose-fully-spec-algs] split signing as defined here (NOTE: Ed448ph not yet registered) |


## HashML-DSA {#ml-dsa-split}

Split HashML-DSA [FIPS-204] uses the following division between the _digester_ and the _signer_
of the steps of the HashML-DSA.Sign algorithm:

- The signing procedure is defined in Section 5.4.1 of [FIPS-204].
- The _digester_ computes the value PH<sub>_M_</sub> defined in Steps 10 to 22 of the signing procedure.
- The message input to the _signer_ is the value PH<sub>_M_</sub> defined in the signing procedure.
  The additional _ctx_ input must also be transmitted to the _signer_.
  This may, for example, be done using the `ctx (-1)` parameter of a `COSE_Key_Ref` with `kty (1): Ref-ML-DSA (TBD)`
  (see {{cose-key-types-reg}} and {{cose-key-type-params-reg}}).
- The _signer_ executes all steps of the signing procedure
  except the Steps 13, 16, 19 or similar that compute the value PH<sub>_M_</sub>.
  Note in particular, that the _signer_ generates the value _rnd_ in Steps 5-8
  and constructs the value _M'_ in Step 23.

The "pure" ML-DSA version [FIPS-204] cannot be divided in this way
because of how the embedding of the _ctx_ and _tr_ values is constructed
in `ML-DSA.Sign` and `ML-DSA.Sign_Internal`.
A division like the one above for HashML-DSA would move control of this embedding from the _signer_ to the _digester_.
This would break the domain separation enforced by the embedding
and possibly enable signature malleability attacks or protocol confusion attacks.

The following algorithm identifiers are defined:

| Name                | COSE Value | Base algorithm | Description |
| ------------------- | ---------- | -------------- | ----------- |
| HashML-DSA-44-split | TBD        | HashML-DSA-44  | HashML-DSA-44 split signing as defined here (NOTE: HashML-DSA-44 not yet registered) |
| HashML-DSA-65-split | TBD        | HashML-DSA-65  | HashML-DSA-65 split signing as defined here (NOTE: HashML-DSA-65 not yet registered) |
| HashML-DSA-87-split | TBD        | HashML-DSA-87  | HashML-DSA-87 split signing as defined here (NOTE: HashML-DSA-87 not yet registered) |


# COSE Key Reference Types {#cose-key-refs}

While keys used by many algorithms can usually be referenced by a single atomic identifier,
such as that used in the `kid` parameter in a COSE_Key object or in the unprotected header of a COSE_Recipient,
some signature algorithms use additional parameters to the signature generation
beyond the signing private key and message to be signed.
For example, ML-DSA [FIPS-204] has the additional parameter _ctx_
and `ARKG-Derive-Private-Key` [I-D.bradleylundberg-ARKG] has the parameters `kh` and `info`, in addition to the private key.

While these additional parameters are simple to provide to the API of the signing procedure
in a single-party context,
in a split signing context these additional parameters also need to be conveyed from the _digester_ to the _signer_.
For this purpose, we define new COSE key types, collectively called "COSE key reference types".
This enables defining a unified, algorithm-agnostic protocol between the _digester_ and the _signer_,
rather than requiring a distinct protocol for each signature algorithm for the sake of conveying algorithm-specific parameters.

A COSE key reference is a COSE_Key object whose `kty` value is defined to represent a reference to a key.
The `kid` parameter MUST be present when `kty` is a key reference type.
These requirements are encoded in the CDDL [RFC8610] type `COSE_Key_Ref`:

~~~cddl
COSE_Key_Ref = COSE_Key .within {
  1 ^ => $COSE_kty_ref   ; kty: Any reference type
  2 ^ => any,            ; kid is required
  any => any,            ; Any other entries allowed by COSE_Key
}
~~~

The following CDDL example represents a reference to an ML-DSA-65 key,
which uses the `AKP` key type [I-D.COSE-ML-DSA],
along with the value of the _ctx_ parameter to ML-DSA.Sign [FIPS-204]:

~~~cddl
{
  1: TBD,      ; kty: Ref-AKP
               ; kid: Opaque identifier of the AKP key
  2: h'92bc2bfa738f5bb07803fb9c0c58020791acd29fbe253baa7a03ac84f4b26d44',

  3: TBD,      ; alg: ML-DSA-65

               ; ctx argument to ML-DSA.Sign
  -1: 'Example application info',
}
~~~


The following CDDL example represents a reference to a key derived by `ARKG-P256ADD-ECDH` [I-D.bradleylundberg-ARKG]
and restricted for use with the ESP256 [I-D.jose-fully-spec-algs] signature algorithm:

~~~cddl
{
  1: -65538,   ; kty: Ref-ARKG-derived
               ; kid: Opaque identifier of ARKG-pub
  2: h'60b6dfddd31659598ae5de49acb220d8
       704949e84d484b68344340e2565337d2',
  3: -9,       ; alg: ESP256

               ; ARKG-P256ADD-ECDH key handle
               ; (HMAC-SHA-256-128 followed by
                  SEC1 uncompressed ECDH public key)
  -1: h'ae079e9c52212860678a7cee25b6a6d4
        048219d973768f8e1adb8eb84b220b0ee3
          a2532828b9aa65254fe3717a29499e9b
          aee70cea75b5c8a2ec2eb737834f7467
          e37b3254776f65f4cfc81e2bc4747a84',

               ; info argument to ARKG-Derive-Private-Key
  -2: 'Example application info',
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

- Name: HashML-DSA-44-split
  - Value: TBD (Requested Assignment -305)
  - Description: HashML-DSA-44 split signing
  - Capabilities: \[kty\]
  - Change Controller: IETF
  - Reference: {{ml-dsa-split}} of this specification
  - Recommended: Yes

- Name: HashML-DSA-65-split
  - Value: TBD (Requested Assignment -306)
  - Description: HashML-DSA-65 split signing
  - Capabilities: \[kty\]
  - Change Controller: IETF
  - Reference: {{ml-dsa-split}} of this specification
  - Recommended: Yes

- Name: HashML-DSA-87-split
  - Value: TBD (Requested Assignment -307)
  - Description: HashML-DSA-87 split signing
  - Capabilities: \[kty\]
  - Change Controller: IETF
  - Reference: {{ml-dsa-split}} of this specification
  - Recommended: Yes


## COSE Key Types Registrations {#cose-key-types-reg}

This section registers the following values in the IANA "COSE Key Types" registry [IANA.COSE]:

- Name: Ref-OKP
  - Value: TBD (Requested assignment -1)
  - Description: Reference to a key pair of key type "OKP"
  - Capabilities: \[kty(-1), crv\]
  - Reference: {{cose-key-refs}} of this specification

- Name: Ref-EC2
  - Value: TBD (Requested assignment -2)
  - Description: Reference to a key pair of key type "EC2"
  - Capabilities: \[kty(-2), crv\]
  - Reference: {{cose-key-refs}} of this specification

- Name: Ref-AKP
  - Value: TBD (Requested assignment -7)
  - Description: Reference to a key pair of key type "AKP"
  - Capabilities: \[kty(TBD), ctx\]
  - Reference: {{cose-key-refs}} of this specification

These registrations add the following choices to the CDDL [RFC8610] type socket `$COSE_kty_ref`:

~~~cddl
$COSE_kty_ref /= -1       ; Value TBD
$COSE_kty_ref /= -2       ; Value TBD
$COSE_kty_ref /= -7       ; Value TBD
~~~


## COSE Key Type Parameters Registrations {#cose-key-type-params-reg}

This section registers the following values in the IANA "COSE Key Type Parameters" registry [IANA.COSE]:

- Key Type: TBD (Ref-AKP)
  - Name: ctx
  - Label: -1
  - CBOR Type: bstr
  - Description: ctx argument to ML-DSA.Sign or HashML-DSA.Sign
  - Reference: {{cose-key-refs}} of this specification


--- back

# Document History
{: numbered="false"}

-02

* Renamed document from "COSE Algorithms for Two-Party Signing" to "Split signing algorithms for COSE"
  and updated introduction and terminology accordingly.

-01

* Added IANA registration requests for algorithms defined.
* Updated references and other editorial tweaks.

-00

* Initial individual draft
