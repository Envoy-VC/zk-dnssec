# zkDNSSEC

**Zero-Knowledge DNSSEC Validation for Trustless, Private DNS**  

---

## Table of Contents  

1. [Overview](#-overview)  
2. [DNS Basics & Problems](#-dns-basics--problems)  
3. [DNSSEC: Cryptographic DNS Security](#️-dnssec-cryptographic-dns-security)  
4. [Architecture & Design](#️-architecture--design)  
5. [Use Cases](#-use-cases)  
6. [Installation & Usage](#️-installation--usage)
7. [Future Roadmap](#-future-roadmap)
8. [Performance & Benchmarks](#performance--benchmarks)

---

## 📜 Overview

`zkdnssec` is a privacy-preserving DNSSEC validator using zero-knowledge proofs (ZKPs). It allows users to prove that a DNS record (e.g., `A`, `TXT`, `CNAME`) is cryptographically signed under DNSSEC rules ([RFC 4034](https://www.rfc-editor.org/rfc/rfc4034)) without revealing the record itself, its signature (RRSIG), or the queried domain name.

### Key Points

1. **Zero-Knowledge DNSSEC**: Prove RRSIG validity while hiding all sensitive DNS data.  
2. **Web3 Compatibility**: Generate proofs verifiable on Ethereum and other EVM chains (Groth16/PLONK).  
3. **Multi-Proof Systems**: Support for SP1(Core/Compressed), Groth16, and PLONK backends.  
4. **RFC 4034 Compliance**: Implements DNSSEC signing/validation logic natively in ZK circuits.  

**Built with**: [Succinct SP1 ZKVM](https://docs.succinct.xyz/docs/sp1/introduction).

---

## 🔍 DNS Basics & Problems

### What is DNS?

The Domain Name System (DNS) is the internet’s phonebook, mapping domains (e.g., `google.com`) to IP addresses. It operates via a distributed hierarchy:  

1. **Recursive Resolvers**: Fetch DNS records from authoritative servers (e.g., Cloudflare, Google DNS).  
2. **Authoritative Servers**: Store DNS records for specific zones (e.g., `.com`, `example.com`).  

### DNS Vulnerabilities  

Traditional DNS has **no security guarantees**:

1. **Spoofing**: Attackers forge DNS responses (e.g., redirect `bank.com` to a phishing site).  
   - *Example*: The 2008 Kaminsky attack exploited DNS cache poisoning.  
2. **No Integrity**: Records can be modified in transit (MITM attacks).  
3. **Cache Poisoning**: Malicious data propagates across resolvers.  
4. **Privacy Leaks**: Queries expose user activity (e.g., `torproject.org` lookups).  

---

## 🛡️ DNSSEC: Cryptographic DNS Security

DNSSEC (DNS Security Extensions) adds cryptographic signatures to DNS records.  

### How DNSSEC Works

1. **Zone Signing**:  
   - A zone owner (e.g., `example.com`) generates:  
     - **Zone Signing Key (ZSK)**: Signs individual DNS records.  
     - **Key Signing Key (KSK)**: Signs the zone’s public keys (DNSKEY).  
   - Each DNS record (e.g., `A 1.2.3.4`) is signed with the ZSK, producing an **RRSIG**.  

2. **Chain of Trust**:  
   - Parent zones (e.g., `.com`) store a **Delegation Signer (DS)** record, a hash of the child zone’s KSK.  
   - Resolvers validate the hierarchy:  
     - Root Zone (`.`) → TLD (`.com`) → Domain (`example.com`).  

3. **Validation Flow**:  
   - A resolver checks:  
     1. The RRSIG matches the DNS record.  
     2. The DNSKEY validates the RRSIG.  
     3. The DS record (from the parent zone) matches the DNSKEY’s hash.  
     4. Recursively verify up to the root zone’s trusted anchor.  

### DNSSEC Limitations

- **Centralized Trust**: Relies on ICANN-controlled root keys.  
- **Privacy Leaks**: Validation exposes queried domains and zone data.

---

## 🏗️ Architecture & Design

### High-Level Workflow

[![High-Level Workflow](https://ethglobal.b-cdn.net/projects/6sd9h/screenshots/1no3i/default.jpg)](https://ethglobal.b-cdn.net/projects/6sd9h/screenshots/1no3i/default.jpg)

### Components

#### 1. Input Data

- **RRset**: The DNS record set (e.g., `example.com. 3600 IN A 1.2.3.4`).  
- **RRSIG**: Signature over the RRset (RFC 4034 format).  
- **DNSKEY**: Public key (ZSK) of the zone.

#### 2. Prover (SP1 ZKVM)

1. **Parsing**:  
   - Extract the RRset, RRSIG, and DNSKEY.  
   - Parse RRSIG fields: Signer Name, Algorithm (e.g., RSA/SHA256), Labels, etc.  
2. **Cryptographic Validation**:  
   - Hash the RRset using the algorithm specified in RRSIG.  
   - Verify the signature against the DNSKEY’s public key.

#### 3. Proof Systems

| Type        | Backend    | Features                 | EVM-Compatible |  
|-------------|------------|----------------------------|----------------|  
| **Core**    | STARK        | List of STARK Proofs   | ❌             |  
| **Compressed**    | STARK        | Constant Sized, small size   | ❌             |  
| **Groth16** | SNARK    | Gas-efficient ~260 bytes     | ✅             |  
| **PLONK**   | SNARK   | No trusted setup, ~868 bytes     | ✅             |

## 💡 Use Cases

- Private Domain Ownership Proof
- Trustless Cross-Chain Bridging: Prove a TXT record (e.g., `_bridge.chain.example.com`) authorizes a cross-chain transaction.
- DNSSEC-Anchored Confidential PKI: Certificate Authorities (CAs) use DNS (CAA/DANE records) to validate domain ownership, but queries leak certificate metadata. Prove a domain’s CAA or TLSA (DANE) record authorizes a TLS certificate without revealing the certificate’s public key or DNS query.
- Light Client Bootstrapping: Light clients (e.g., Ethereum LES) rely on DNS for peer discovery, exposing them to sybil attacks. Validate peer lists via DNSSEC-signed ENR (Ethereum Node Records) with ZK proofs, ensuring peers are legitimate without trusting resolvers.
- and many more...

---

## 🛠️ Installation & Usage

### Requirements

- Rust 1.81+
- SP1 ZKVM
- Foundry (for EVM verifiers)

### Usage

To execute the Circuit, navigate to the `scripts` directory and run:

```bash
cargo run -- --execute
```

This will execute the circuit and print the output to the console. (This does not produce a proof.)

To generate a proof, navigate to the `scripts` directory and run:

```bash
cargo run -- --prove {mode}
```

Mode can be one of the following:

- `core`: Generate a STARK proof using the Core backend.
- `compressed`: Generate a STARK proof using the Compressed backend.
- `groth16`: Generate a Groth16 proof.
- `plonk`: Generate a PLONK proof.

example:

```bash
# Generate a Core proof
cargo run -- --prove core
# Generate a Compressed proof
cargo run -- --prove compressed
# Generate a Groth16 proof
cargo run -- --prove groth16
# Generate a PLONK proof
cargo run -- --prove plonk
```

More Args can be found in [entrypoint.rs](./scripts//src//entrypoint.rs).

### EVM Verification

To test the foundry Contracts, navigate to the `contracts` directory and run:

```bash
forge test -vv
```

---

## 🌟 Future Roadmap

- Recursive Chain of Trust: Validate root → TLD → domain in a single ZK proof.
- Authenticated Denial: NSEC/NSEC3 proofs to non-existence of DNS records.

---

## Performance & Benchmarks

> The current implementation is not optimized for performance. For execution it takes around **270k** cycles. Though this will be optimized in the future, on average it can take around **100k** cycles to execute production-ready circuits.

---
