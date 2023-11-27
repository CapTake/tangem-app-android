package com.tangem.feature.wallet.presentation.wallet.state2.transformers

import com.tangem.domain.tokens.error.TokenListError
import com.tangem.domain.wallets.models.UserWalletId
import com.tangem.feature.wallet.presentation.wallet.state2.WalletState
import com.tangem.feature.wallet.presentation.wallet.state2.WalletTokensListState
import timber.log.Timber

/**
 * @author Andrew Khokhlov on 16/11/2023
 */
internal class SetTokenListErrorTransformer(
    userWalletId: UserWalletId,
    private val error: TokenListError,
) : WalletStateTransformer(userWalletId) {

    override fun transform(prevState: WalletState): WalletState {
        return when (error) {
            is TokenListError.EmptyTokens -> {
                when (prevState) {
                    is WalletState.MultiCurrency.Content -> {
                        prevState.copy(tokensListState = WalletTokensListState.Empty)
                    }
                    is WalletState.SingleCurrency.Content -> {
                        Timber.e("Impossible to load tokens list for single-currency wallet")
                        prevState
                    }
                    is WalletState.MultiCurrency.Locked,
                    is WalletState.SingleCurrency.Locked,
                    -> {
                        Timber.e("Impossible to load tokens list for locked wallet")
                        prevState
                    }
                }
            }
            is TokenListError.DataError,
            is TokenListError.UnableToSortTokenList,
            -> prevState
        }
    }
}
