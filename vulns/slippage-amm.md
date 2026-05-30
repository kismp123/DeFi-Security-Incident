# Slippage & AMM

Missing or bypassable slippage protection in AMMs, allowing sandwich attacks or unfavorable trade execution.

**Total incidents: 26**

---

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2021-02-04 | Yearn | yDAI CurvePoolImbalance | [2021-02-04_Yearn_yDAI_CurvePoolImbalance.md](../2021/2021-02-04_Yearn_yDAI_CurvePoolImbalance.md) |
| 2021-04-28 | Uranium | Finance KInvariantMismatch | [2021-04-28_Uranium_Finance_KInvariantMismatch.md](../2021/2021-04-28_Uranium_Finance_KInvariantMismatch.md) |
| 2021-05-02 | Spartan | Protocol SpotBalanceLPCalc | [2021-05-02_Spartan_Protocol_SpotBalanceLPCalc.md](../2021/2021-05-02_Spartan_Protocol_SpotBalanceLPCalc.md) |
| 2021-06-26 | xWin | SlippageControl Bypass | [2021-06-26_xWin_SlippageControl_Bypass.md](../2021/2021-06-26_xWin_SlippageControl_Bypass.md) |
| 2021-09-21 | Nimbus | KInvariant 1000vs10000 | [2021-09-21_Nimbus_KInvariant_1000vs10000.md](../2021/2021-09-21_Nimbus_KInvariant_1000vs10000.md) |
| 2022-04-30 | Saddle | StableSwapArbitrage | [2022-04-30_Saddle_StableSwapArbitrage.md](../2022/2022-04-30_Saddle_StableSwapArbitrage.md) |
| 2023-05-28 | BabyDogeCoin | SlippageProtection BSC | [2023-05-28_BabyDogeCoin_SlippageProtection_BSC.md](../2023/2023-05-28_BabyDogeCoin_SlippageProtection_BSC.md) |
| 2023-05-28 | JimbosProtocol | SlippageExploit ARB | [2023-05-28_JimbosProtocol_SlippageExploit_ARB.md](../2023/2023-05-28_JimbosProtocol_SlippageExploit_ARB.md) |
| 2023-11-06 | TheStandard | SlippageProtection ARB | [2023-11-06_TheStandard_SlippageProtection_ARB.md](../2023/2023-11-06_TheStandard_SlippageProtection_ARB.md) |
| 2023-12-05 | BEARNDAO | SlippageProtection BSC | [2023-12-05_BEARNDAO_SlippageProtection_BSC.md](../2023/2023-12-05_BEARNDAO_SlippageProtection_BSC.md) |
| 2024-06-02 | Velocore | InvariantFlaw zkSync | [2024-06-02_Velocore_InvariantFlaw_zkSync.md](../2024/2024-06-02_Velocore_InvariantFlaw_zkSync.md) |
| 2024-09-16 | Inferno | SlippageProtection ETH | [2024-09-16_Inferno_SlippageProtection_ETH.md](../2024/2024-09-16_Inferno_SlippageProtection_ETH.md) |
| 2024-10-05 | EGAToken | SlippageProtection BSC | [2024-10-05_EGAToken_SlippageProtection_BSC.md](../2024/2024-10-05_EGAToken_SlippageProtection_BSC.md) |
| 2024-11-24 | DCFToken | SlippageProtection BSC | [2024-11-24_DCFToken_SlippageProtection_BSC.md](../2024/2024-11-24_DCFToken_SlippageProtection_BSC.md) |
| 2025-02-07 | ADACash | SlippageProtection BSC | [2025-02-07_ADACash_SlippageProtection_BSC.md](../2025/2025-02-07_ADACash_SlippageProtection_BSC.md) |
| 2025-03-01 | ZeUSD | SlippageProtection ETH | [2025-03-01_ZeUSD_SlippageProtection_ETH.md](../2025/2025-03-01_ZeUSD_SlippageProtection_ETH.md) |
| 2025-10-20 | SharwaFinance | SlippageManipulation | [2025-10-20_SharwaFinance_BusinessLogic_ARB.md](../2025/2025-10-20_SharwaFinance_BusinessLogic_ARB.md) |
| 2025-11-10 | DRLVaultV3 | SlippageAmm ETH | [2025-11-10_DRLVaultV3_SlippageAmm_ETH.md](../2025/2025-11-10_DRLVaultV3_SlippageAmm_ETH.md) |
| 2022-10-27 | TeamFinance | MigrateSqrtPrice | [2022-10-27_TeamFinance_MigrateSqrtPrice.md](../2022/2022-10-27_TeamFinance_MigrateSqrtPrice.md) |
| 2022-11 | BDEX | ConvertDustManipulation | [2022-11_BDEX_ConvertDustManipulation.md](../2022/2022-11_BDEX_ConvertDustManipulation.md) |
| 2022-12-02 | Overnight | USDPlusPlatypusManipulation | [2022-12-02_Overnight_USDPlusPlatypusManipulation.md](../2022/2022-12-02_Overnight_USDPlusPlatypusManipulation.md) |
| 2023-06-05 | VINU | AddLiquidityExploit | [2023-06-05_VINU_AddLiquidityExploit.md](../2023/2023-06-05_VINU_AddLiquidityExploit.md) |
| 2024-04-XX | Z123 | ConsecutiveSwapLiquidityBurn | [2024-04-XX_Z123_ConsecutiveSwapLiquidityBurn.md](../2024/2024-04-XX_Z123_ConsecutiveSwapLiquidityBurn.md) |
| 2025-06-23 | GradientMakerPool | LiquidityImbalance | [2025-06-23_GradientMakerPool_LiquidityImbalance.md](../2025/2025-06-23_GradientMakerPool_LiquidityImbalance.md) |
| 2026-02-22 | LAXOToken | LPBurnManipulation BSC | [2026-02-22_LAXOToken_LPBurnManipulation_BSC.md](../2026/2026-02-22_LAXOToken_LPBurnManipulation_BSC.md) |
| 2026-04-07 | HERMES | HB PoolTaxDrain AMM k Zero | [2026-04-07_HERMES_HB_PoolTaxDrain_AMM_k_Zero.md](../2026/2026-04-07_HERMES_HB_PoolTaxDrain_AMM_k_Zero.md) |

---

[← Back to vulnerability index](./README.md)
