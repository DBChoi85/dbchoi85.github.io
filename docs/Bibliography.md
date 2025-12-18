# Smart Contract Vulnerabilities – Real Cases & Vulnerable Code Examples (15 Types)
# References – Smart Contract Vulnerabilities

This document lists the primary references used to identify, explain, and exemplify the 15 smart contract vulnerability and incident patterns described in this work.  
The sources below are widely accepted standards in smart contract security research, auditing, and real-world incident analysis.

---

## 1. Official Language & Platform Documentation

### Solidity Documentation
- **Solidity Security Considerations**  
  https://docs.soliditylang.org/en/latest/security-considerations.html  
  Covers core security concepts such as reentrancy, delegatecall risks, arithmetic issues, timestamp dependence, and randomness.

- **Solidity Storage Layout**  
  https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html  
  Essential reference for understanding storage collisions, uninitialized storage pointers, and delegatecall-related issues.

---

## 2. Vulnerability Taxonomy & Classification Standards

### SWC Registry (Smart Contract Weakness Classification)
- https://swcregistry.io  

The SWC Registry serves as a de facto standard taxonomy for smart contract vulnerabilities and is frequently referenced by auditors and automated analysis tools.

Relevant SWC entries include:
- SWC-107: Reentrancy  
- SWC-101: Integer Overflow and Underflow  
- SWC-105: Unchecked Call Return Value  
- SWC-112: Delegatecall to Untrusted Callee  
- SWC-116: Block Timestamp Dependence  
- SWC-120: Weak Sources of Randomness  
- SWC-124: Write to Arbitrary Storage Location  

---

## 3. Historical Exploits and Incident Analyses

### The DAO Hack (2016)
- https://blog.ethereum.org/2016/06/17/critical-update-re-dao-vulnerability  
- https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/  

Canonical real-world example of a reentrancy attack leading to catastrophic fund loss.

### Parity Multisig Wallet Hacks (2017)
- https://paritytech.io/blog/security-alert.html  
- https://medium.com/@kaisercrazy/the-parity-wallet-hack-explained-3c8a2b9a20c1  

Illustrates delegatecall misuse and insecure initialization in proxy–library patterns.

### BatchOverflow Vulnerability (2018)
- https://peckshield.com/2018/04/22/batchOverflow/  

Demonstrates integer overflow in ERC-20 batch transfer logic enabling massive token minting.

### King of the Ether Throne
- https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/  

Classic denial-of-service attack caused by reverting fallback functions.

---

## 4. DeFi Exploits: Oracle, MEV, and Logic Failures

### bZx Protocol Exploits (2020)
- https://bzx.network/blog/postmortem-ethdenver  
- https://rekt.news/bzx-rekt/  

Flash-loan-powered oracle manipulation exploiting AMM-based price feeds.

### Harvest Finance Exploit (2020)
- https://rekt.news/harvest-finance-rekt/  

Price oracle manipulation via temporary liquidity distortion.

### Compound COMP Distribution Bug (2021)
- https://www.comp.xyz/t/incident-analysis-2021-09-30/2991  

A business logic error causing unintended over-distribution of governance tokens.

---

## 5. Security Best Practices & Audit Guidelines

### ConsenSys – Smart Contract Best Practices
- https://consensys.github.io/smart-contract-best-practices/  

Comprehensive security guidance covering reentrancy, access control, DoS, randomness, input validation, and secure design patterns.

### OpenZeppelin Documentation
- https://docs.openzeppelin.com/contracts  

Industry-standard reference implementations for ERC tokens, access control, upgradeable contracts, and secure initialization patterns.

---

## 6. Ethereum Improvement Proposals (ERC Standards)

### ERC-20 Token Standard
- https://eips.ethereum.org/EIPS/eip-20  

Defines required token behaviors, including return values and revert semantics.

### ERC-721 Non-Fungible Token Standard
- https://eips.ethereum.org/EIPS/eip-721  

### ERC-1155 Multi-Token Standard
- https://eips.ethereum.org/EIPS/eip-1155  

Deviation from these standards frequently causes integration failures and security issues.

---

## 7. Academic Research & Systematic Studies

### Flash Loans and DeFi Attacks
- https://arxiv.org/abs/2009.14021  

Academic analysis of flash-loan-enabled attack vectors, including oracle manipulation.

### SoK: Decentralized Finance (SoK: DeFi)
- https://arxiv.org/abs/2101.08778  

Systematization of knowledge on DeFi risks, including MEV, oracle failures, and protocol composability.

---

## 8. Practical Audit Perspective

The 15 vulnerability patterns covered in this document represent the intersection of:
- SWC Registry high-impact categories  
- ConsenSys Best Practices critical risks  
- OpenZeppelin audit checklists  
- Repeated patterns observed in major post-mortem analyses  

As such, they are suitable for use in:
- Smart contract audit reports  
- Developer security training  
- Internal security standards  
- Academic or applied research

---
