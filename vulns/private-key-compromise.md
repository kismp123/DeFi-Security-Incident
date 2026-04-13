# Private Key Compromise

Incidents where privileged private keys were stolen, leaked, or abused — bypassing on-chain access controls entirely at the infrastructure or operational level.

**Total incidents: 12**

---

## External Key Theft

Attacker obtained private keys via hacking, phishing, or operational security failures.

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2021-03-07 | PAID Network | PrivateKeyCompromise UnauthorizedMint | [2021-03-07_PAID_Network_UnauthorizedMint.md](../2021/2021-03-07_PAID_Network_UnauthorizedMint.md) |
| 2021-07-20 | Levyathan | GitHubKeyLeak MintOwnership | [2021-07-20_Levyathan_PrivateKeyLeak_MintOwnership.md](../2021/2021-07-20_Levyathan_PrivateKeyLeak_MintOwnership.md) |
| 2022-03-23 | Ronin | CompromisedValidatorKeys | [2022-03-23_Ronin_CompromisedValidatorSignatures.md](../2022/2022-03-23_Ronin_CompromisedValidatorSignatures.md) |
| 2022-06-23 | Harmony | CompromisedMultisig | [2022-06-23_Harmony_CompromisedMultisig.md](../2022/2022-06-23_Harmony_CompromisedMultisig.md) |
| 2022-06-24 | HarmonyBridge | MultisigKeyCompromise | [2022-06-24_HarmonyBridge_MultisigKeyCompromise.md](../2022/2022-06-24_HarmonyBridge_MultisigKeyCompromise.md) |

---

## Insider / Rug Pull

Protocol deployer or team member abused privileged key access.

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2021-09-17 | SushiMiso | InsiderContractorHijack | [2021-09-17_SushiMiso_DutchAuction_AccessControl.md](../2021/2021-09-17_SushiMiso_DutchAuction_AccessControl.md) |
| 2025-03-25 | YziAIToken | DeployerBackdoor | [2025-03-25_YziAIToken_Backdoor.md](../2025/2025-03-25_YziAIToken_Backdoor.md) |
| 2025-05-13 | IRYSAI | RugPullDeployer | [2025-05-13_IRYSAI_Rugpull.md](../2025/2025-05-13_IRYSAI_Rugpull.md) |
| 2025-05-21 | YDTToken | HiddenSelectorDeployer | [2025-05-21_YDTToken_SpecialSelector.md](../2025/2025-05-21_YDTToken_SpecialSelector.md) |

---

## Supply Chain / Infrastructure Compromise

Attacker tampered with off-chain infrastructure to steal keys or bypass key-based authorization.

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2025-07-15 | BigONE | SupplyChainWithdrawalLogic | [2025-07-15_BigONE_Exploit_ETH.md](../2025/2025-07-15_BigONE_Exploit_ETH.md) |
| 2025-12-24 | TrustWallet | NpmSupplyChainSeedPhrase | [2025-12-24_TrustWallet_Exploit_ETH.md](../2025/2025-12-24_TrustWallet_Exploit_ETH.md) |
| 2022-06-09 | Optimism | WintermuteVanityAddress | [2022-06-09_Optimism_WintermuteVanityAddress.md](../2022/2022-06-09_Optimism_WintermuteVanityAddress.md) |

---

[← Back to vulnerability index](./README.md)
