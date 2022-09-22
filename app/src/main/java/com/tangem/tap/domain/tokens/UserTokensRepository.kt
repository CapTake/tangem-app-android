package com.tangem.tap.domain.tokens

import android.content.Context
import com.tangem.blockchain.common.DerivationStyle
import com.tangem.common.card.Card
import com.tangem.common.extensions.calculateSha256
import com.tangem.common.extensions.toHexString
import com.tangem.common.services.Result
import com.tangem.domain.common.extensions.calculateHmacSha256
import com.tangem.network.api.tangemTech.TangemTechService
import com.tangem.tap.common.AndroidFileReader
import com.tangem.tap.domain.NoDataError
import com.tangem.tap.domain.tokens.models.BlockchainNetwork
import com.tangem.tap.features.demo.DemoHelper
import com.tangem.tap.features.wallet.models.Currency
import com.tangem.tap.features.wallet.models.toBlockchainNetworks
import com.tangem.tap.features.wallet.models.toCurrencies
import com.tangem.tap.network.NetworkConnectivity
import com.tangem.tap.store
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

class UserTokensRepository(
    private val storageService: UserTokensStorageService,
    private val networkService: UserTokensNetworkService,
) {
    suspend fun getUserTokens(card: Card): Result<List<Currency>> {
        if (DemoHelper.isDemoCardId(card.cardId)) {
            return Result.Success(loadDemoCurrencies())
        }
        val userId = card.getUserId()
        if (!NetworkConnectivity.getInstance().isOnlineOrConnecting()) {
            return Result.Success(loadTokensOffline(card, userId))
        }

        return when (val networkResult = networkService.getUserTokens(userId)) {
            is Result.Success -> {
                val tokens = networkResult.data.tokens.map { Currency.fromTokenResponse(it) }
                storageService.saveUserTokens(card.getUserId(), tokens)
                Result.Success(tokens)
            }
            is Result.Failure -> {
                handleGetUserTokensFailure(card = card, userId = userId, error = networkResult.error)
            }
        }
    }

    suspend fun saveUserTokens(card: Card, tokens: List<Currency>) {
        networkService.saveUserTokens(card.getUserId(), tokens)
        storageService.saveUserTokens(card.getUserId(), tokens)
    }

    suspend fun removeUserTokens(card: Card) {
        networkService.saveUserTokens(card.getUserId(), emptyList())
        storageService.saveUserTokens(card.getUserId(), emptyList())
    }

    fun loadBlockchainsToDerive(card: Card): List<BlockchainNetwork> {
        return storageService.getUserTokens(card.getUserId())?.toBlockchainNetworks() ?: emptyList()
    }

    private fun loadDemoCurrencies(): List<Currency> {
        return DemoHelper.config.demoBlockchains.map {
            BlockchainNetwork(
                blockchain = it,
                derivationPath = it.derivationPath(DerivationStyle.LEGACY)?.rawPath,
                tokens = emptyList(),
            )
        }.flatMap { it.toCurrencies() }
    }

    private suspend fun handleGetUserTokensFailure(
        card: Card,
        userId: String,
        error: Throwable,
    ): Result<List<Currency>> {
        return when (error) {
            is NoDataError -> {
                val tokens = storageService.getUserTokens(card)
                coroutineScope { launch { networkService.saveUserTokens(userId = userId, tokens = tokens) } }
                Result.Success(tokens)
            }
            else -> {
                val tokens = storageService.getUserTokens(userId) ?: storageService.getUserTokens(card)
                Result.Success(tokens)
            }
        }
    }

    private suspend fun loadTokensOffline(card: Card, userId: String): List<Currency> {
        return storageService.getUserTokens(userId) ?: storageService.getUserTokens(card)
    }

    private fun Card.getUserId(): String {
        val walletPublicKey = this.wallets.firstOrNull()?.publicKey ?: return ""
        return calculateUserId(walletPublicKey)
    }

    private fun calculateUserId(walletPublicKey: ByteArray): String {
        val message = MESSAGE.toByteArray()
        val keyHash = walletPublicKey.calculateSha256()
        return message.calculateHmacSha256(keyHash).toHexString()
    }

    companion object {
        const val MESSAGE = "AccountID"
        fun init(context: Context, tangemTechService: TangemTechService): UserTokensRepository {
            val fileReader = AndroidFileReader(context)
            val oldUserTokensRepository = OldUserTokensRepository(
                fileReader, store.state.domainNetworks.tangemTechService,
            )
            val storageService = UserTokensStorageService(oldUserTokensRepository, fileReader)
            val networkService = UserTokensNetworkService(tangemTechService)
            return UserTokensRepository(storageService, networkService)
        }
    }
}
