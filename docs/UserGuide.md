# xDAO CATF User Guide

> **Canonical Attestation Text Format (CATF) – Civilization-Grade Evidence & Resolution**

This document is a **complete, standalone guide** to understanding and using the xDAO CATF core library. A reader should be able to read *only this document* and understand **what CATF is**, **why it exists**, **the principles it enforces**, and **how to use the library correctly**.

---

## Executive Summary — What CATF Is Really About

CATF exists to solve a problem that traditional systems avoid:

> **How do we preserve truth, evidence, and disagreement across decades or centuries without relying on centralized authority, continuous networks, or fragile institutions?**

CATF is **not** a database schema, blockchain, or API protocol.

CATF is a **civilization-grade evidence format** designed to:

* Preserve *what was asserted*, *by whom*, and *about what*
* Allow independent systems to converge on the same conclusions
* Make disagreement visible rather than destructive
* Survive institutional collapse, cryptographic change, and software loss

CATF treats **evidence as immutable**, **trust as policy**, and **resolution as deterministic reasoning**.

This library implements CATF and its supporting mechanisms as a **core, API-safe library**.

---

## 1. What CATF Is (And Is Not)

### CATF Is

* A **human-legible, canonical text format** for attestations
* A **cryptographically verifiable affidavit system**
* A **truth-preserving memory substrate**
* A foundation for law, science, records, and governance

### CATF Is Not

* A blockchain or distributed ledger
* A token or economic system
* A consensus or voting protocol
* A real-time execution engine
* A replacement for legal or institutional judgment

CATF records **evidence**, not enforcement.

---

## 2. Core Concepts

### 2.1 Document

A **Document** is any immutable artifact addressed by content:

* PDF
* text file
* image
* dataset

Documents are identified by a **CID (Content Identifier)** derived from cryptographic hashing.

---

### 2.2 Attestation (CATF)

An **Attestation** is a signed statement expressed in CATF that asserts something about:

* a document
* another attestation
* a symbolic name

Attestations are:

* immutable
* append-only
* content-addressed

CATF is the **authoritative representation** of an attestation.

---

### 2.3 Trust Policy (TPDL)

Trust is **not encoded in CATF**.

Trust is expressed separately using a **Trust Policy**, written in the Trust Policy Domain Language (TPDL).

A policy defines:

* which keys are trusted
* what roles they may assert
* quorum requirements

This separation ensures trust can evolve without rewriting history.

---

### 2.4 Resolver

A **Resolver** applies:

* a set of attestations
* a trust policy
* optional context

to produce a **deterministic resolution**.

Resolvers are **pure functions**.

---

### 2.5 CROF (Canonical Resolver Output Format)

A **CROF** document records the *result of resolution*.

CROF is:

* canonical
* human-readable
* archivable
* signable

CROF is **evidence of interpretation**, not truth.

---

## 3. Guiding Principles

### 3.1 Canonical Truth

Canonical bytes matter more than data structures.

If two systems produce different bytes, they do not agree.

---

### 3.2 Forks Are Truth

Disagreement is preserved.

CATF never forces convergence.

---

### 3.3 Cryptography Is Evidence

Cryptography proves *who said something*, not *whether it is true*.

---

### 3.4 No Global Roots

There is no central authority, registry, or root of trust.

---

### 3.5 Determinism Above All

Given the same inputs, every resolver must produce the same output.

---

## 4. Technologies Used

The CATF library intentionally uses a **minimal technology stack**:

* **Plain text** (human survivability)
* **Ed25519** (identity and signing)
* **SHA-256** (content addressing)
* **Content Identifiers (CIDs)**
* **Deterministic algorithms only**

No databases, networks, or blockchains are required.

---

## 5. Library Architecture Overview

The library is organized into clear subsystems:

* `catf` — parsing and canonicalization
* `resolver` — deterministic resolution
* `tpdl` — trust policy parsing
* `crof` — canonical resolution output
* `keys` — minimal key management

Each subsystem is deterministic and independent.

---

## 6. Typical Usage Flow

1. Store a document (produce CID)
2. Create CATF attestations about the document
3. Write a trust policy
4. Run the resolver
5. Produce CROF
6. Archive or verify later

---

## 7. Key Management (KMS-lite)

The library includes a minimal key system:

* Root identity keys
* Role-scoped derived keys
* Local-first storage

There are no accounts, passwords, or recovery mechanisms.

Loss of keys = loss of authority (by design).

---

## 8. Name Resolution (DNS-for-Documents)

Symbolic names are bound to CIDs via attestations.

Names:

* are advisory
* are forkable
* never override content authority

Name resolution always passes through trust policy.

---

## 9. Compliance Modes

The library supports **strict compliance mode**.

In strict mode:

* ambiguity is rejected
* defaults are illegal
* forks are always surfaced

Strict mode is recommended for archival and legal use.

---

## 10. Failure & Degradation

CATF is designed to degrade safely:

* Missing evidence → reduced confidence
* Conflicting evidence → forks
* Lost networks → offline resolution
* Broken crypto → preserved semantics

Nothing is silently erased.

---

## 11. What This Library Does Not Do

This library does **not**:

* enforce legal outcomes
* move money
* execute contracts
* decide truth

Those responsibilities belong to people and institutions.

---

## 12. When to Use CATF

Use CATF when you need:

* Long-term record integrity
* Auditability across systems
* Independence from centralized trust
* Explicit handling of disagreement

---

## 13. Mental Model

> **CATF records what was said.**
> **Policies record what is trusted.**
> **Resolvers compute what follows.**
> **CROF records what was believed — and why.**

---

## 14. Final Notes

This library is intentionally conservative.

It values:

* correctness over convenience
* durability over performance
* clarity over cleverness

If you treat CATF as infrastructure rather than a product, it will outlive you.

---

**End of User Guide**
