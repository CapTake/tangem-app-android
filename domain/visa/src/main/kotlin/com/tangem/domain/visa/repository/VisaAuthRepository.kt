package com.tangem.domain.visa.repository

import com.tangem.domain.visa.model.VisaAuthChallenge
import com.tangem.domain.visa.model.VisaAuthSignedChallenge
import com.tangem.domain.visa.model.VisaAuthTokens

interface VisaAuthRepository {

    suspend fun getCardAuthChallenge(
        cardId: String,
        cardPublicKey: String,
    ): com.tangem.domain.visa.model.VisaAuthChallenge.Card

    suspend fun getCustomerWalletAuthChallenge(
        cardId: String,
        walletPublicKey: String,
    ): com.tangem.domain.visa.model.VisaAuthChallenge.Wallet

    suspend fun getAccessTokens(
        signedChallenge: com.tangem.domain.visa.model.VisaAuthSignedChallenge,
    ): com.tangem.domain.visa.model.VisaAuthTokens
}
