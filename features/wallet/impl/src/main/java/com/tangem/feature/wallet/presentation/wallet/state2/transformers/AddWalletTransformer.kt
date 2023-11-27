package com.tangem.feature.wallet.presentation.wallet.state2.transformers

import com.tangem.domain.wallets.models.UserWallet
import com.tangem.feature.wallet.presentation.wallet.state2.WalletScreenState
import com.tangem.feature.wallet.presentation.wallet.viewmodels.intents.WalletClickIntentsV2
import kotlinx.collections.immutable.toImmutableList

/**
 * @author Andrew Khokhlov on 22/11/2023
 */
internal class AddWalletTransformer(
    private val userWallet: UserWallet,
    private val clickIntents: WalletClickIntentsV2,
) : WalletScreenStateTransformer {

    private val walletStateFactory by lazy {
        WalletStateFactory(
            clickIntents = clickIntents,
        )
    }

    override fun transform(prevState: WalletScreenState): WalletScreenState {
        return prevState.copy(
            wallets = (prevState.wallets + walletStateFactory.createLoadingState(userWallet)).toImmutableList(),
        )
    }
}
