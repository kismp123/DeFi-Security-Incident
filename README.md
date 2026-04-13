# DeFi Security Incident Database

A comprehensive reference of **887** real-world DeFi security incidents (2020–2026), with root cause analysis, attack flow diagrams, on-chain source code, and PoC exploit code.

---

## Browse by Year

| Year | Incidents | Notable Events |
|------|-----------|----------------|
| [2020](./2020/README.md) | 9 | ERC777 reentrancy, early DeFi exploits |
| [2021](./2021/README.md) | 34 | Flash loan surge, BSC explosion, K-invariant bypasses |
| [2022](./2022/README.md) | 135 | Bridge mega-hacks — Ronin ($625M), Wormhole ($320M), Nomad ($190M) |
| [2023](./2023/README.md) | 266 | Flash loans, read-only reentrancy on L2, high-volume year |
| [2024](./2024/README.md) | 279 | Business logic & arbitrary call dominance on BSC/ETH |
| [2025](./2025/README.md) | 128 | Complex multi-step exploits, precision loss, AMM bugs |
| [2026](./2026/README.md) | 36 | BSC business logic, EIP-7702, AMM k-value attacks |

---

## Browse by Vulnerability Type

| Category | Incidents | Description |
|----------|-----------|-------------|
| [Flash Loan](./vulns/flash-loan.md) | 116 | Price manipulation and logic exploits within a single transaction |
| [Business Logic](./vulns/business-logic.md) | 99 | Protocol-specific flaws in accounting, rewards, or invariants |
| [Oracle & Price Manipulation](./vulns/oracle-price-manipulation.md) | 93 | Spot price distortion, reserve skewing, TWAP gaming |
| [Access Control](./vulns/access-control.md) | 86 | Missing or bypassed permission checks on privileged functions |
| [Reentrancy](./vulns/reentrancy.md) | 72 | Cross-function and read-only reentrancy attacks |
| [Arbitrary Call / Input](./vulns/arbitrary-call.md) | 60 | Attacker-controlled calldata hijacking execution flow |
| [Staking & Reward](./vulns/staking-reward.md) | 28 | Reward math errors, lock-up bypass, vault logic flaws |
| [Integer & Precision](./vulns/integer-precision.md) | 25 | Overflow, underflow, and fixed-point precision bugs |
| [Slippage & AMM](./vulns/slippage-amm.md) | 18 | Missing slippage protection, K-invariant bypass |
| [Deflationary / Tax Token](./vulns/defl-tax-token.md) | 16 | Protocol incompatibility with rebase/fee-on-transfer tokens |
| [Signature Replay](./vulns/signature-replay.md) | 14 | Reused signatures missing nonces or domain separators |
| [Proxy & Storage Collision](./vulns/proxy-storage.md) | 10 | Storage layout mismatches between proxy and implementation |
| [Governance](./vulns/governance.md) | 8 | Flash-loan governance, vote manipulation |
| [NFT](./vulns/nft.md) | 7 | Reentrancy via callbacks, royalty bypass |
| [Bridge & Cross-Chain](./vulns/bridge-crosschain.md) | 1 | Cross-chain message validation failures |
| [Other](./vulns/other.md) | 234 | Protocol-specific and miscellaneous exploits |

→ [Full vulnerability type index](./vulns/README.md)

---

## Report Format

Each incident file (`YYYY-MM-DD_<Protocol>_<VulnType>.md`) contains:

1. **Vulnerability Overview** — Root cause and financial impact
2. **Vulnerable Code Analysis** — Vulnerable vs. fixed code comparison
3. **On-chain Source Code** — Actual deployed contract snippets
4. **Attack Flow** — ASCII step-by-step exploit diagram
5. **PoC Code** — Foundry-based exploit with inline comments
6. **Vulnerability Classification** — CWE, OWASP DeFi, attack vector
7. **Remediation** — Concrete fix recommendations
8. **Lessons Learned** — Key takeaways for developers and auditors

---

## Sources

- PoC references: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)
- On-chain data: Etherscan, BSCScan, Polygonscan, and other explorers
- Contract source: Sourcify, Etherscan verified contracts

---

*For educational and research purposes only.*
