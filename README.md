# Authenticated Diffie-Hellman Key Exchange (Midterm 2 Project)

A local Python simulation of an authenticated finite-field Diffie-Hellman key
exchange between Alice and Bob, with an attacker (Eve) who controls the
simulated network. This is an educational project, not a production protocol.

## Environment and versions

Versions used for the demo output and test results:

| Item            | Version |
|-----------------|---------|
| Python          | 3.12.10 |
| cryptography    | 50.0.2  |
| pycryptodome    | 4.2.0   |
| OS              | Windows |

To find the versions:

```
python --version
python -m pip show cryptography pycryptodome
```

## Setup

```
python -m pip install -r requirements.txt
```

or install the packages directly:

```
python -m pip install cryptography pycryptodome
```

Note: install `pycryptodome`, not `pycrypto`. Both are imported as `Crypto`,
and the old package can conflict.

## Run

Run the demonstration (successful exchange, Eve's attack against the
unauthenticated version, Eve's rejected attack against the authenticated
version, and the 16/24/32-bit performance table):

```
python auth_dh_compact.py
```

To save the output as sample output files:

```
python auth_dh_compact.py > sample_output.txt
```

## Test

```
python auth_dh_compact.py test
```

The tests are grouped into fixed mathematical tests, prime-generator
integration tests, message validation tests, and complete exchange tests.

## What the program does

| Step | Component | Implemented by |
|------|-----------|----------------|
| 1 | Square-and-multiply modular exponentiation | Own code |
| 2 | Prime generation (16-32 bits) and received-modulus validation | PyCryptodome `getPrime` / `isPrime` |
| 3 | Factorization of p - 1 (trial division) | Own code |
| 4 | Generator verification and search | Own code |
| 5 | Diffie-Hellman key generation and shared secrets | Own code |
| 6 | Ed25519 signing identities and trusted-key lookup | `cryptography` library |
| 7 | Deterministic JSON messages, strict validation, nonces | Own code |
| 8 | Three signed messages: init, response, finish | Own code |
| 9 | Shared-secret calculation and check (local test only) | Own code |
| 10 | Eve's attacks and rejection tests | Own code |

Python's three-argument `pow` is used only inside tests as an independent
reference.

## Protocol summary

1. **Init (Alice -> Bob):** Alice generates p, g, a, A and nonce_A, and signs
   the init payload. Bob checks format, size, protocol, identities and Alice's
   signature, then validates p (library primality check), factors p - 1,
   verifies g, and checks A is in range.
2. **Response (Bob -> Alice):** Bob generates b, B and nonce_B and signs the
   full transcript (protocol, identities, p, g, A, B, nonce_A, nonce_B).
   Alice confirms p, g, A and nonce_A match her pending session, checks B,
   and verifies Bob's signature.
3. **Finish (Alice -> Bob):** Alice signs the same transcript. Bob requires an
   exact match with his pending transcript. Duplicate, stale or mismatched
   finishes are rejected.

Messages are encoded with
`json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")`,
limited to 4096 bytes, and validated against fixed schemas with no type
coercion and no duplicate JSON keys. Nonces are 32 random bytes encoded as
64-character hex strings.

## Trust assumptions

- Alice and Bob each hold the other's authentic Ed25519 public key through a
  trusted setup step before the exchange.
- Eve controls simulated network messages but cannot change the trusted key
  configuration or read private keys.
- Private exponents never appear in simulated network messages. They appear
  only in clearly labeled classroom debug output.

## Results that are reported separately

The program reports these outcomes as separate facts:

```
Transcript authenticated: YES
Shared secrets match in local test: YES
Explicit key confirmation: NOT IMPLEMENTED
```

Signatures authenticate the transcript. They do not prove that either side
computed the shared secret.

## Limitations

- 16-32 bit primes are trivially breakable by brute force. Signatures detect
  tampering under the trust assumptions, but they do not make these small
  parameters confidential.
- Factoring p - 1 by trial division is only practical because the primes are
  small.
- The custom exponentiation is not constant-time.
- Range checks on public values are basic classroom checks, not a complete
  production group-validation policy.
- No message encryption, sockets, ECDH implementation, or explicit key
  confirmation is included.
- Real applications should use established authenticated protocols and
  cryptographic libraries.

## Files

| File | Purpose |
|------|---------|
| `auth_dh_compact.py` | All source code, demo, timing and automated tests |
| `requirements.txt` | Dependency versions |
| `README.md` | This file |
