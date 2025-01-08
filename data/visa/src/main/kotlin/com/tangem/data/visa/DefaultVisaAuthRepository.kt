package com.tangem.data.visa

import com.tangem.datasource.api.visa.TangemVisaAuthApi
import com.tangem.domain.visa.model.VisaAuthChallenge
import com.tangem.domain.visa.model.VisaAuthSession
import com.tangem.domain.visa.model.VisaAuthSignedChallenge
import com.tangem.domain.visa.model.VisaAuthTokens
import com.tangem.domain.visa.repository.VisaAuthRepository
import com.tangem.utils.coroutines.CoroutineDispatcherProvider
import kotlinx.coroutines.withContext
import javax.inject.Inject

internal class DefaultVisaAuthRepository @Inject constructor(
    private val visaAuthApi: TangemVisaAuthApi,
    private val dispatchers: CoroutineDispatcherProvider,
) : VisaAuthRepository {

    override suspend fun getCardAuthChallenge(
        cardId: String,
        cardPublicKey: String,
    ): com.tangem.domain.visa.model.VisaAuthChallenge.Card = withContext(dispatchers.io) {
        val response = visaAuthApi.generateNonceByCard(
            cardId = cardId,
            cardPublicKey = cardPublicKey,
        )

        com.tangem.domain.visa.model.VisaAuthChallenge.Card(
            challenge = response.nonce,
            session = com.tangem.domain.visa.model.VisaAuthSession(response.sessionId),
        )
    }

    override suspend fun getCustomerWalletAuthChallenge(
        cardId: String,
        walletPublicKey: String,
    ): com.tangem.domain.visa.model.VisaAuthChallenge.Wallet = withContext(dispatchers.io) {
        val response = visaAuthApi.generateNonceByWalletAddress(
            customerId = cardId,
            customerWalletAddress = walletPublicKey,
        )

        com.tangem.domain.visa.model.VisaAuthChallenge.Wallet(
            challenge = response.nonce,
            session = com.tangem.domain.visa.model.VisaAuthSession(response.sessionId),
        )
    }

    override suspend fun getAccessTokens(
        signedChallenge: com.tangem.domain.visa.model.VisaAuthSignedChallenge,
    ): com.tangem.domain.visa.model.VisaAuthTokens = withContext(dispatchers.io) {
        val response = when (signedChallenge) {
            is com.tangem.domain.visa.model.VisaAuthSignedChallenge.ByCardPublicKey -> {
                visaAuthApi.getAccessToken(
                    sessionId = signedChallenge.challenge.session.sessionId,
                    signature = signedChallenge.signature,
                    salt = signedChallenge.salt,
                )
            }
            is com.tangem.domain.visa.model.VisaAuthSignedChallenge.ByWallet -> {
                visaAuthApi.getAccessToken(
                    sessionId = signedChallenge.challenge.session.sessionId,
                    signature = signedChallenge.signature,
                    salt = null,
                )
            }
        }

        com.tangem.domain.visa.model.VisaAuthTokens(
            accessToken = response.accessToken,
            refreshToken = response.refreshToken,
        )
    }
}
