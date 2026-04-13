# 2025 DeFi Security Incidents

Access control and business logic errors persisted. More complex multi-step exploits emerged alongside precision loss bugs and AMM-specific vulnerabilities.

**Total incidents: 128**

---

## Top Vulnerability Types

| Type | Count |
|------|-------|
| BusinessLogic ETH | 6 |
| BusinessLogic BSC | 6 |
| AccessControl ETH | 5 |
| Exploit ETH | 4 |
| PriceManipulation | 2 |
| BusinessLogic ARB | 2 |
| SlippageManipulation | 2 |
| LiquidityManipulation | 1 |
| UnprotectedSwap | 1 |
| RewardCalculationFlaw | 1 |

---

## Incident List

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2025-01-06 | LAURAToken | LiquidityManipulation | [2025-01-06_LAURAToken_LiquidityManipulation.md](./2025-01-06_LAURAToken_LiquidityManipulation.md) |
| 2025-01-07 | 98Token | UnprotectedSwap | [2025-01-07_98Token_UnprotectedSwap.md](./2025-01-07_98Token_UnprotectedSwap.md) |
| 2025-01-08 | SorraStaking | RewardCalculationFlaw | [2025-01-08_SorraStaking_RewardCalculationFlaw.md](./2025-01-08_SorraStaking_RewardCalculationFlaw.md) |
| 2025-01-10 | HORS | InsufficientInputValidation | [2025-01-10_HORS_InsufficientInputValidation.md](./2025-01-10_HORS_InsufficientInputValidation.md) |
| 2025-01-10 | IPC | ChainedFlashLoanTimelockBypass | [2025-01-10_IPC_ChainedFlashLoanTimelockBypass.md](./2025-01-10_IPC_ChainedFlashLoanTimelockBypass.md) |
| 2025-01-10 | Mosca | FlashLoanStateManipulation | [2025-01-10_Mosca_FlashLoanStateManipulation.md](./2025-01-10_Mosca_FlashLoanStateManipulation.md) |
| 2025-01-11 | LPMine | UnboundedRewardClaim | [2025-01-11_LPMine_UnboundedRewardClaim.md](./2025-01-11_LPMine_UnboundedRewardClaim.md) |
| 2025-01-12 | UniLend | AccountingError ETH | [2025-01-12_UniLend_AccountingError_ETH.md](./2025-01-12_UniLend_AccountingError_ETH.md) |
| 2025-01-13 | JPulsepot | ProfitFeeSwapManipulation | [2025-01-13_JPulsepot_ProfitFeeSwapManipulation.md](./2025-01-13_JPulsepot_ProfitFeeSwapManipulation.md) |
| 2025-01-14 | RoulettePotV2 | RoundFinishManipulation | [2025-01-14_RoulettePotV2_RoundFinishManipulation.md](./2025-01-14_RoulettePotV2_RoundFinishManipulation.md) |
| 2025-01-14 | TheIdolsNFT | BusinessLogic ETH | [2025-01-14_TheIdolsNFT_BusinessLogic_ETH.md](./2025-01-14_TheIdolsNFT_BusinessLogic_ETH.md) |
| 2025-01-15 | Unilend | HealthFactorMiscalculation | [2025-01-15_Unilend_HealthFactorMiscalculation.md](./2025-01-15_Unilend_HealthFactorMiscalculation.md) |
| 2025-01-17 | Mosca2 | FlashLoanJoinExit | [2025-01-17_Mosca2_FlashLoanJoinExit.md](./2025-01-17_Mosca2_FlashLoanJoinExit.md) |
| 2025-01-20 | IdolsNFT | SelfTransferRewardDrain | [2025-01-20_IdolsNFT_SelfTransferRewardDrain.md](./2025-01-20_IdolsNFT_SelfTransferRewardDrain.md) |
| 2025-01-22 | Paribus | NFTCollateralOvervaluation | [2025-01-22_Paribus_NFTCollateralOvervaluation.md](./2025-01-22_Paribus_NFTCollateralOvervaluation.md) |
| 2025-01-25 | ASTToken | DoubleSkim | [2025-01-25_ASTToken_DoubleSkim.md](./2025-01-25_ASTToken_DoubleSkim.md) |
| 2025-01-27 | ODOS | ERC6492SignatureBypass | [2025-01-27_ODOS_ERC6492SignatureBypass.md](./2025-01-27_ODOS_ERC6492SignatureBypass.md) |
| 2025-02-03 | PeapodsFinance | TokenRewardManipulation | [2025-02-03_PeapodsFinance_TokenRewardManipulation.md](./2025-02-03_PeapodsFinance_TokenRewardManipulation.md) |
| 2025-02-07 | ADACash | SlippageProtection BSC | [2025-02-07_ADACash_SlippageProtection_BSC.md](./2025-02-07_ADACash_SlippageProtection_BSC.md) |
| 2025-02-10 | FourMeme | PoolCreationFrontrun | [2025-02-10_FourMeme_PoolCreationFrontrun.md](./2025-02-10_FourMeme_PoolCreationFrontrun.md) |
| 2025-02-11 | FourMeMe | BusinessLogic BSC | [2025-02-11_FourMeMe_BusinessLogic_BSC.md](./2025-02-11_FourMeMe_BusinessLogic_BSC.md) |
| 2025-02-12 | Unverified | d4f1 UninitializedProxy | [2025-02-12_Unverified_d4f1_UninitializedProxy.md](./2025-02-12_Unverified_d4f1_UninitializedProxy.md) |
| 2025-02-22 | StepHeroNFTs | ClaimReferralReentrancy | [2025-02-22_StepHeroNFTs_ClaimReferralReentrancy.md](./2025-02-22_StepHeroNFTs_ClaimReferralReentrancy.md) |
| 2025-02-23 | HegicOptions | BusinessLogic ETH | [2025-02-23_HegicOptions_BusinessLogic_ETH.md](./2025-02-23_HegicOptions_BusinessLogic_ETH.md) |
| 2025-02-26 | HegicOptions | WithdrawWithoutHedge | [2025-02-26_HegicOptions_WithdrawWithoutHedge.md](./2025-02-26_HegicOptions_WithdrawWithoutHedge.md) |
| 2025-02-28 | Venus | ZKSync DonationAttack | [2025-02-28_Venus_ZKSync_DonationAttack.md](./2025-02-28_Venus_ZKSync_DonationAttack.md) |
| 2025-03-01 | DCFToken | FlashLoanManipulation | [2025-03-01_DCFToken_FlashLoanManipulation.md](./2025-03-01_DCFToken_FlashLoanManipulation.md) |
| 2025-03-01 | ZeUSD | SlippageProtection ETH | [2025-03-01_ZeUSD_SlippageProtection_ETH.md](./2025-03-01_ZeUSD_SlippageProtection_ETH.md) |
| 2025-03-05 | 1inchFusionV1 | BusinessLogic ETH | [2025-03-05_1inchFusionV1_BusinessLogic_ETH.md](./2025-03-05_1inchFusionV1_BusinessLogic_ETH.md) |
| 2025-03-05 | PumpToken | BuyTokenReentrancy | [2025-03-05_PumpToken_BuyTokenReentrancy.md](./2025-03-05_PumpToken_BuyTokenReentrancy.md) |
| 2025-03-07 | DUCKVADER | FeeManipulation | [2025-03-07_DUCKVADER_FeeManipulation.md](./2025-03-07_DUCKVADER_FeeManipulation.md) |
| 2025-03-10 | OneInchFusion | CalldataCorruption | [2025-03-10_OneInchFusion_CalldataCorruption.md](./2025-03-10_OneInchFusion_CalldataCorruption.md) |
| 2025-03-14 | H2O | PriceManipulation | [2025-03-14_H2O_PriceManipulation.md](./2025-03-14_H2O_PriceManipulation.md) |
| 2025-03-15 | SBRToken | FeeOnTransferSkimExploit | [2025-03-15_SBRToken_FeeOnTransferSkimExploit.md](./2025-03-15_SBRToken_FeeOnTransferSkimExploit.md) |
| 2025-03-15 | wKeyDAO | NFTReentrancy | [2025-03-15_wKeyDAO_NFTReentrancy.md](./2025-03-15_wKeyDAO_NFTReentrancy.md) |
| 2025-03-18 | Alkimiya | MorphoFlashLoan | [2025-03-18_Alkimiya_MorphoFlashLoan.md](./2025-03-18_Alkimiya_MorphoFlashLoan.md) |
| 2025-03-20 | BBXToken | BurnMechanism | [2025-03-20_BBXToken_BurnMechanism.md](./2025-03-20_BBXToken_BurnMechanism.md) |
| 2025-03-20 | UNI | SamPrisonman FeeOnTransferSkim | [2025-03-20_UNI_SamPrisonman_FeeOnTransferSkim.md](./2025-03-20_UNI_SamPrisonman_FeeOnTransferSkim.md) |
| 2025-03-21 | LeverageSIR | Create2Exploit | [2025-03-21_LeverageSIR_Create2Exploit.md](./2025-03-21_LeverageSIR_Create2Exploit.md) |
| 2025-03-25 | MIMSpell | CauldronRounding ARB | [2025-03-25_MIMSpell_CauldronRounding_ARB.md](./2025-03-25_MIMSpell_CauldronRounding_ARB.md) |
| 2025-03-25 | YziAIToken | Backdoor | [2025-03-25_YziAIToken_Backdoor.md](./2025-03-25_YziAIToken_Backdoor.md) |
| 2025-03-30 | LeverageSir | StorageCollision ETH | [2025-03-30_LeverageSir_StorageCollision_ETH.md](./2025-03-30_LeverageSir_StorageCollision_ETH.md) |
| 2025-04-01 | OPC | BusinessLogic BSC | [2025-04-01_OPC_BusinessLogic_BSC.md](./2025-04-01_OPC_BusinessLogic_BSC.md) |
| 2025-04-04 | AIRWA | BurnRateManipulation | [2025-04-04_AIRWA_BurnRateManipulation.md](./2025-04-04_AIRWA_BurnRateManipulation.md) |
| 2025-04-08 | Laundromat | WithdrawReentrancy | [2025-04-08_Laundromat_WithdrawReentrancy.md](./2025-04-08_Laundromat_WithdrawReentrancy.md) |
| 2025-04-10 | MorphoBlue | Misconfiguration ETH | [2025-04-10_MorphoBlue_Misconfiguration_ETH.md](./2025-04-10_MorphoBlue_Misconfiguration_ETH.md) |
| 2025-04-11 | Unverified6077 | CallbackExploit | [2025-04-11_Unverified6077_CallbackExploit.md](./2025-04-11_Unverified6077_CallbackExploit.md) |
| 2025-04-14 | KiloEx | AccessControl Base | [2025-04-14_KiloEx_AccessControl_Base.md](./2025-04-14_KiloEx_AccessControl_Base.md) |
| 2025-04-14 | YBToken | FlashLoanKManipulation | [2025-04-14_YBToken_FlashLoanKManipulation.md](./2025-04-14_YBToken_FlashLoanKManipulation.md) |
| 2025-04-15 | BTNFT | TransferAccessControl | [2025-04-15_BTNFT_TransferAccessControl.md](./2025-04-15_BTNFT_TransferAccessControl.md) |
| 2025-04-17 | Roar | EmergencyWithdrawExploit | [2025-04-17_Roar_EmergencyWithdrawExploit.md](./2025-04-17_Roar_EmergencyWithdrawExploit.md) |
| 2025-04-24 | ZoraToken | BusinessLogic Base | [2025-04-24_ZoraToken_BusinessLogic_Base.md](./2025-04-24_ZoraToken_BusinessLogic_Base.md) |
| 2025-04-26 | ImpermaxFinance | BusinessLogic ARB | [2025-04-26_ImpermaxFinance_BusinessLogic_ARB.md](./2025-04-26_ImpermaxFinance_BusinessLogic_ARB.md) |
| 2025-04-28 | Lifeprotocol | PriceManipulation | [2025-04-28_Lifeprotocol_PriceManipulation.md](./2025-04-28_Lifeprotocol_PriceManipulation.md) |
| 2025-05-08 | Nalakuvara | LotteryTicketDrain | [2025-05-08_Nalakuvara_LotteryTicketDrain.md](./2025-05-08_Nalakuvara_LotteryTicketDrain.md) |
| 2025-05-11 | MBUToken | BusinessLogic BSC | [2025-05-11_MBUToken_BusinessLogic_BSC.md](./2025-05-11_MBUToken_BusinessLogic_BSC.md) |
| 2025-05-12 | MBUToken | DepositMint | [2025-05-12_MBUToken_DepositMint.md](./2025-05-12_MBUToken_DepositMint.md) |
| 2025-05-13 | IRYSAI | Rugpull | [2025-05-13_IRYSAI_Rugpull.md](./2025-05-13_IRYSAI_Rugpull.md) |
| 2025-05-15 | Unwarp | WETHUnwrapExploit | [2025-05-15_Unwarp_WETHUnwrapExploit.md](./2025-05-15_Unwarp_WETHUnwrapExploit.md) |
| 2025-05-19 | KRCToken | SkimManipulation | [2025-05-19_KRCToken_SkimManipulation.md](./2025-05-19_KRCToken_SkimManipulation.md) |
| 2025-05-21 | YDTToken | SpecialSelector | [2025-05-21_YDTToken_SpecialSelector.md](./2025-05-21_YDTToken_SpecialSelector.md) |
| 2025-05-22 | RICE | BentoBoxWithdraw | [2025-05-22_RICE_BentoBoxWithdraw.md](./2025-05-22_RICE_BentoBoxWithdraw.md) |
| 2025-05-27 | UsualMoney | VaultPriceArbitrage | [2025-05-27_UsualMoney_VaultPriceArbitrage.md](./2025-05-27_UsualMoney_VaultPriceArbitrage.md) |
| 2025-05-28 | CorkProtocol | AccessControl ETH | [2025-05-28_CorkProtocol_AccessControl_ETH.md](./2025-05-28_CorkProtocol_AccessControl_ETH.md) |
| 2025-05-30 | Malda | AccessControl Linea | [2025-05-30_Malda_AccessControl_Linea.md](./2025-05-30_Malda_AccessControl_Linea.md) |
| 2025-06-09 | Unverified8490 | FlashLoanCallback | [2025-06-09_Unverified8490_FlashLoanCallback.md](./2025-06-09_Unverified8490_FlashLoanCallback.md) |
| 2025-06-11 | AAVEBoost | ProxyDepositDrain | [2025-06-11_AAVEBoost_ProxyDepositDrain.md](./2025-06-11_AAVEBoost_ProxyDepositDrain.md) |
| 2025-06-14 | BankrollNetwork | DonatePoolExploit | [2025-06-14_BankrollNetwork_DonatePoolExploit.md](./2025-06-14_BankrollNetwork_DonatePoolExploit.md) |
| 2025-06-14 | BankrollStack | FlashLoanDividendDrain | [2025-06-14_BankrollStack_FlashLoanDividendDrain.md](./2025-06-14_BankrollStack_FlashLoanDividendDrain.md) |
| 2025-06-17 | MetaPool | AccessControl ETH | [2025-06-17_MetaPool_AccessControl_ETH.md](./2025-06-17_MetaPool_AccessControl_ETH.md) |
| 2025-06-19 | Gangsterfinance | DonateDepositExploit | [2025-06-19_Gangsterfinance_DonateDepositExploit.md](./2025-06-19_Gangsterfinance_DonateDepositExploit.md) |
| 2025-06-23 | GradientMakerPool | LiquidityImbalance | [2025-06-23_GradientMakerPool_LiquidityImbalance.md](./2025-06-23_GradientMakerPool_LiquidityImbalance.md) |
| 2025-06-25 | MEVBot | 0xB5CB05 AccessControl BSC | [2025-06-25_MEVBot_0xB5CB05_AccessControl_BSC.md](./2025-06-25_MEVBot_0xB5CB05_AccessControl_BSC.md) |
| 2025-06-25 | ResupplyFi | OracleManipulation | [2025-06-25_ResupplyFi_OracleManipulation.md](./2025-06-25_ResupplyFi_OracleManipulation.md) |
| 2025-06-25 | SiloFinance | ArbitraryCall Sonic | [2025-06-25_SiloFinance_ArbitraryCall_Sonic.md](./2025-06-25_SiloFinance_ArbitraryCall_Sonic.md) |
| 2025-06-26 | Resupply | PrecisionLoss ETH | [2025-06-26_Resupply_PrecisionLoss_ETH.md](./2025-06-26_Resupply_PrecisionLoss_ETH.md) |
| 2025-06-27 | Stead | AccessControlMissing | [2025-06-27_Stead_AccessControlMissing.md](./2025-06-27_Stead_AccessControlMissing.md) |
| 2025-07-01 | FPC | TokenPriceManipulation | [2025-07-01_FPC_TokenPriceManipulation.md](./2025-07-01_FPC_TokenPriceManipulation.md) |
| 2025-07-02 | FutureProtocol | BusinessLogic BSC | [2025-07-02_FutureProtocol_BusinessLogic_BSC.md](./2025-07-02_FutureProtocol_BusinessLogic_BSC.md) |
| 2025-07-04 | RANTToken | ReflectionManipulation | [2025-07-04_RANTToken_ReflectionManipulation.md](./2025-07-04_RANTToken_ReflectionManipulation.md) |
| 2025-07-05 | RANT | BusinessLogic BSC | [2025-07-05_RANT_BusinessLogic_BSC.md](./2025-07-05_RANT_BusinessLogic_BSC.md) |
| 2025-07-08 | PeapodsFinance | PriceDependency ETH | [2025-07-08_PeapodsFinance_PriceDependency_ETH.md](./2025-07-08_PeapodsFinance_PriceDependency_ETH.md) |
| 2025-07-09 | GMX | UnverifiedInput ARB | [2025-07-09_GMX_UnverifiedInput_ARB.md](./2025-07-09_GMX_UnverifiedInput_ARB.md) |
| 2025-07-09 | ZKSwap | BusinessLogic ETH | [2025-07-09_ZKSwap_BusinessLogic_ETH.md](./2025-07-09_ZKSwap_BusinessLogic_ETH.md) |
| 2025-07-10 | GMX | GlpPriceManipulation | [2025-07-10_GMX_GlpPriceManipulation.md](./2025-07-10_GMX_GlpPriceManipulation.md) |
| 2025-07-14 | VDS | MoolahFlashLoanExploit | [2025-07-14_VDS_MoolahFlashLoanExploit.md](./2025-07-14_VDS_MoolahFlashLoanExploit.md) |
| 2025-07-15 | BigONE | Exploit ETH | [2025-07-15_BigONE_Exploit_ETH.md](./2025-07-15_BigONE_Exploit_ETH.md) |
| 2025-07-17 | Stepp2p | FlashLoanLogicFlaw | [2025-07-17_Stepp2p_FlashLoanLogicFlaw.md](./2025-07-17_Stepp2p_FlashLoanLogicFlaw.md) |
| 2025-07-17 | WETC | DoubleAccounting BSC | [2025-07-17_WETC_DoubleAccounting_BSC.md](./2025-07-17_WETC_DoubleAccounting_BSC.md) |
| 2025-07-19 | SWAPPStaking | CompoundExploit | [2025-07-19_SWAPPStaking_CompoundExploit.md](./2025-07-19_SWAPPStaking_CompoundExploit.md) |
| 2025-07-22 | MulticallWithETH | ValueForwarding | [2025-07-22_MulticallWithETH_ValueForwarding.md](./2025-07-22_MulticallWithETH_ValueForwarding.md) |
| 2025-07-25 | WETC | Token PancakeSwapCallback | [2025-07-25_WETC_Token_PancakeSwapCallback.md](./2025-07-25_WETC_Token_PancakeSwapCallback.md) |
| 2025-07-28 | SuperRare | AccessControl ETH | [2025-07-28_SuperRare_AccessControl_ETH.md](./2025-07-28_SuperRare_AccessControl_ETH.md) |
| 2025-08-01 | WXC | Token MoolahFlashLoanCallback | [2025-08-01_WXC_Token_MoolahFlashLoanCallback.md](./2025-08-01_WXC_Token_MoolahFlashLoanCallback.md) |
| 2025-08-06 | YuliAI | FlashLoan-PriceManipulation | [2025-08-06_YuliAI_FlashLoan-PriceManipulation.md](./2025-08-06_YuliAI_FlashLoan-PriceManipulation.md) |
| 2025-08-07 | Bebop | dex ArbitraryTransferFrom | [2025-08-07_Bebop_dex_ArbitraryTransferFrom.md](./2025-08-07_Bebop_dex_ArbitraryTransferFrom.md) |
| 2025-08-07 | SizeCredit | ArbitraryCall | [2025-08-07_SizeCredit_ArbitraryCall.md](./2025-08-07_SizeCredit_ArbitraryCall.md) |
| 2025-08-08 | PDZ | FlashLoan-RewardManipulation | [2025-08-08_PDZ_FlashLoan-RewardManipulation.md](./2025-08-08_PDZ_FlashLoan-RewardManipulation.md) |
| 2025-08-09 | d3xai | PriceManipulation-TaxToken | [2025-08-09_d3xai_PriceManipulation-TaxToken.md](./2025-08-09_d3xai_PriceManipulation-TaxToken.md) |
| 2025-08-10 | 0x8d2e | MissingAccessControl-SwapCallback | [2025-08-10_0x8d2e_MissingAccessControl-SwapCallback.md](./2025-08-10_0x8d2e_MissingAccessControl-SwapCallback.md) |
| 2025-08-13 | Coinbase | ExcessiveApprovalDrain | [2025-08-13_Coinbase_ExcessiveApprovalDrain.md](./2025-08-13_Coinbase_ExcessiveApprovalDrain.md) |
| 2025-08-13 | Grizzifi | TeamCountManipulation | [2025-08-13_Grizzifi_TeamCountManipulation.md](./2025-08-13_Grizzifi_TeamCountManipulation.md) |
| 2025-08-13 | MulticallWithXera | ApprovalAbuse | [2025-08-13_MulticallWithXera_ApprovalAbuse.md](./2025-08-13_MulticallWithXera_ApprovalAbuse.md) |
| 2025-08-19 | ABCCApp | RewardTokenExploit | [2025-08-19_ABCCApp_RewardTokenExploit.md](./2025-08-19_ABCCApp_RewardTokenExploit.md) |
| 2025-08-20 | 0xf340 | MissingAccessControl-VRF | [2025-08-20_0xf340_MissingAccessControl-VRF.md](./2025-08-20_0xf340_MissingAccessControl-VRF.md) |
| 2025-08-22 | EverValueCoin | OrderbookManipulation | [2025-08-22_EverValueCoin_OrderbookManipulation.md](./2025-08-22_EverValueCoin_OrderbookManipulation.md) |
| 2025-08-23 | Equilibria | BusinessLogic ETH | [2025-08-23_Equilibria_BusinessLogic_ETH.md](./2025-08-23_Equilibria_BusinessLogic_ETH.md) |
| 2025-08-25 | Hexotic | FlashSwap-TakeFunction | [2025-08-25_Hexotic_FlashSwap-TakeFunction.md](./2025-08-25_Hexotic_FlashSwap-TakeFunction.md) |
| 2025-08-28 | Panoptic | Exploit ETH | [2025-08-28_Panoptic_Exploit_ETH.md](./2025-08-28_Panoptic_Exploit_ETH.md) |
| 2025-08-29 | CozyFinance | BusinessLogic OP | [2025-08-29_CozyFinance_BusinessLogic_OP.md](./2025-08-29_CozyFinance_BusinessLogic_OP.md) |
| 2025-09-24 | NGP | ReflectionToken-Manipulation | [2025-09-24_NGP_ReflectionToken-Manipulation.md](./2025-09-24_NGP_ReflectionToken-Manipulation.md) |
| 2025-10-04 | Abracadabra | BusinessLogic ETH | [2025-10-04_Abracadabra_BusinessLogic_ETH.md](./2025-10-04_Abracadabra_BusinessLogic_ETH.md) |
| 2025-10-15 | MIMSpell3 | BorrowLimitBypass | [2025-10-15_MIMSpell3_BorrowLimitBypass.md](./2025-10-15_MIMSpell3_BorrowLimitBypass.md) |
| 2025-10-20 | SharwaFinance | BusinessLogic ARB | [2025-10-20_SharwaFinance_BusinessLogic_ARB.md](./2025-10-20_SharwaFinance_BusinessLogic_ARB.md) |
| 2025-10-22 | TokenHolder | PrivilegedLoan-Exploit | [2025-10-22_TokenHolder_PrivilegedLoan-Exploit.md](./2025-10-22_TokenHolder_PrivilegedLoan-Exploit.md) |
| 2025-10-30 | SharwaFinance | SlippageManipulation | [2025-10-30_SharwaFinance_SlippageManipulation.md](./2025-10-30_SharwaFinance_SlippageManipulation.md) |
| 2025-11-03 | BalancerV2 | PrecisionLoss ARB | [2025-11-03_BalancerV2_PrecisionLoss_ARB.md](./2025-11-03_BalancerV2_PrecisionLoss_ARB.md) |
| 2025-11-04 | DexodusFinance | PriceDependency Base | [2025-11-04_DexodusFinance_PriceDependency_Base.md](./2025-11-04_DexodusFinance_PriceDependency_Base.md) |
| 2025-11-05 | BalancerV2 | StableMath-Overflow | [2025-11-05_BalancerV2_StableMath-Overflow.md](./2025-11-05_BalancerV2_StableMath-Overflow.md) |
| 2025-11-10 | DRLVaultV3 | AccessControl ETH | [2025-11-10_DRLVaultV3_AccessControl_ETH.md](./2025-11-10_DRLVaultV3_AccessControl_ETH.md) |
| 2025-11-12 | DRLVaultV3 | SlippageManipulation | [2025-11-12_DRLVaultV3_SlippageManipulation.md](./2025-11-12_DRLVaultV3_SlippageManipulation.md) |
| 2025-11-20 | Moonwell | OracleManipulation-Chainlink | [2025-11-20_Moonwell_OracleManipulation-Chainlink.md](./2025-11-20_Moonwell_OracleManipulation-Chainlink.md) |
| 2025-11-30 | Yearn | VaultExploit ETH | [2025-11-30_Yearn_VaultExploit_ETH.md](./2025-11-30_Yearn_VaultExploit_ETH.md) |
| 2025-12-02 | Goldfinch | Exploit ETH | [2025-12-02_Goldfinch_Exploit_ETH.md](./2025-12-02_Goldfinch_Exploit_ETH.md) |
| 2025-12-10 | yETH | VirtualBalance-Manipulation | [2025-12-10_yETH_VirtualBalance-Manipulation.md](./2025-12-10_yETH_VirtualBalance-Manipulation.md) |
| 2025-12-11 | SixSevenPrism | BusinessLogic BSC | [2025-12-11_SixSevenPrism_BusinessLogic_BSC.md](./2025-12-11_SixSevenPrism_BusinessLogic_BSC.md) |
| 2025-12-12 | RibbonFinance | AccessControl ETH | [2025-12-12_RibbonFinance_AccessControl_ETH.md](./2025-12-12_RibbonFinance_AccessControl_ETH.md) |
| 2025-12-24 | TrustWallet | Exploit ETH | [2025-12-24_TrustWallet_Exploit_ETH.md](./2025-12-24_TrustWallet_Exploit_ETH.md) |

---

[← Back to main index](../README.md)
