# JetonRouter — Arbitrary Call Router Token Drain

| Item | Details |
|------|------|
| **Date** | 2026-04-28 |
| **Protocol** | JetonRouter |
| **Chain** | Ethereum |
| **Loss** | ~$229K |
| **Root Cause** | Arbitrary External Call — DEX router executes arbitrary external calls with user-controlled calldata, allowing attacker to drain tokens approved by users to the router |
| **Attack Tx** | `0x57709a498f27c7219b634ae20e7d2cbf9ab8dd6aca7b3845fabf93b57760b576` |
| **Reference** | [TenArmorAlert on X](https://x.com/TenArmorAlert/status/2048943311113552370) |

---

## 1. Vulnerability Overview

JetonRouter is a DEX aggregator/router on Ethereum. A business logic flaw in the routing mechanism allowed an attacker to extract ~$229K. DEX aggregator routers that forward user-supplied calldata to arbitrary target contracts are a well-known vulnerability class: users grant token approvals to the router so it can pull their funds during swaps, but if the router will execute any call to any target, an attacker can craft calldata that calls `transferFrom(victim, attacker, balance)` on tokens the victim has approved.

The flaw does not require any flash loan or complex setup. The attacker simply needs to construct calldata that, when executed by the router in the context of a "swap", redirects approved user tokens to the attacker's address. The router's legitimate purpose — pulling tokens from users and forwarding them to DEX pools — becomes the attack vector when the target and calldata are not validated against a whitelist of known-safe combinations.

## 2. Vulnerable Code Analysis

```solidity
// VULNERABLE — arbitrary call with user-controlled target and calldata
function swap(
    address target,
    bytes calldata data,
    address tokenIn,
    uint256 amountIn
) external {
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    // BUG: executes arbitrary call — attacker supplies target = tokenAddress
    // and data = transferFrom(victim, attacker, victimBalance) to steal
    // tokens that any user has approved to this router contract
    (bool success,) = target.call(data);
    require(success);
}

// FIXED — whitelist targets and validate output
function swap(
    address target,
    bytes calldata data,
    address tokenIn,
    uint256 amountIn,
    address tokenOut,
    uint256 minAmountOut
) external {
    require(approvedTargets[target], "target not whitelisted");
    // Reject calldata whose first 4 bytes are transferFrom selector
    require(bytes4(data) != IERC20.transferFrom.selector, "forbidden selector");
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    uint256 before = IERC20(tokenOut).balanceOf(address(this));
    (bool success,) = target.call(data);
    require(success);
    uint256 received = IERC20(tokenOut).balanceOf(address(this)) - before;
    require(received >= minAmountOut, "insufficient output");
    IERC20(tokenOut).transfer(msg.sender, received);
}
```

The fixed version restricts `target` to a whitelist of known DEX contracts, rejects dangerous selectors, and enforces a minimum output amount — ensuring the router cannot be weaponized against its own users' approvals.

## 3. Attack Flow

1. Attacker identifies users who have approved JetonRouter for a token (e.g., USDC) with a large allowance, by scanning Approval events on Etherscan.
2. Attacker calls `swap(USDC_address, transferFrom_calldata, USDC, 0)` where `transferFrom_calldata` encodes `transferFrom(victim, attacker, victimBalance)`.
3. The router executes `USDC.call(transferFrom(victim, attacker, victimBalance))` — succeeds because the router is the `msg.sender` and USDC approvals to the router were granted by the victim.
4. Victim's USDC balance is transferred to the attacker with the router as the intermediary.
5. Attacker repeats for each victim address with outstanding approvals until ~$229K is drained.

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Business Logic Flaw — Arbitrary External Call / Unvalidated Calldata |
| **Severity** | High |
| **CWE** | CWE-20 (Improper Input Validation) |

## 5. Remediation Recommendations

- Maintain a strict whitelist of approved target addresses (known DEX routers and pool contracts); reject any call where `target` is not on the whitelist.
- Block dangerous function selectors (`transferFrom`, `transfer`, `approve`) from appearing as the leading 4 bytes of forwarded calldata; routers should never forward calls that move tokens on behalf of other addresses.
- After any external call, verify that the router received the expected `tokenOut` amount and that its `tokenIn` balance is not higher than before the call — preventing attacker-crafted calls from leaving residual balances or stealing approved tokens from other users.

## References

- [TenArmorAlert — X post](https://x.com/TenArmorAlert/status/2048943311113552370)
- [Etherscan — Attack Tx](https://etherscan.io/tx/0x57709a498f27c7219b634ae20e7d2cbf9ab8dd6aca7b3845fabf93b57760b576)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
