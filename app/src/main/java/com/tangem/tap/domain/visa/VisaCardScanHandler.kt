package com.tangem.tap.domain.visa

import com.tangem.common.CompletionResult
import com.tangem.common.card.CardWallet
import com.tangem.common.core.CardSession
import com.tangem.common.core.TangemSdkError
import com.tangem.common.extensions.toHexString
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey
import com.tangem.domain.common.visa.VisaUtilities
import com.tangem.domain.visa.model.VisaActivationInput
import com.tangem.domain.visa.model.VisaAuthSignedChallenge
import com.tangem.domain.visa.model.VisaCardActivationStatus
import com.tangem.domain.visa.model.toSignedChallenge
import com.tangem.domain.visa.repository.VisaAuthRepository
import com.tangem.operations.attestation.AttestCardKeyCommand
import com.tangem.operations.attestation.AttestCardKeyResponse
import com.tangem.operations.derivation.DeriveWalletPublicKeyTask
import com.tangem.operations.sign.SignHashCommand
import com.tangem.operations.sign.SignHashResponse
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import timber.log.Timber

internal class VisaCardScanHandler(
    private val visaAuthRepository: VisaAuthRepository,
    private val coroutineScope: CoroutineScope,
) {

    fun handleVisaCardScan(
        session: CardSession,
        callback: (result: CompletionResult<VisaCardActivationStatus>) -> Unit,
    ) {
        Timber.i("Attempting to handle Visa card scan")

        val card = session.environment.card ?: run {
            Timber.e("Card is null")
            callback(CompletionResult.Failure(TangemSdkError.MissingPreflightRead()))
            return
        }

        val wallet = card.wallets.firstOrNull { it.curve == VisaUtilities.mandatoryCurve } ?: run {
            val activationInput =
                VisaActivationInput(card.cardId, card.cardPublicKey, card.isAccessCodeSet)
            val activationStatus = VisaCardActivationStatus.NotStartedActivation(activationInput)
            callback(CompletionResult.Success(activationStatus))
            return
        }

        deriveKey(wallet, session, callback)
    }

    private fun deriveKey(
        wallet: CardWallet,
        session: CardSession,
        callback: (result: CompletionResult<VisaCardActivationStatus>) -> Unit,
    ) {
        val derivationPath = VisaUtilities.visaDefaultDerivationPath ?: run {
            Timber.e("Failed to create derivation path while first scan")
            callback(
                CompletionResult.Failure(
                    TangemSdkError.Underlying(VisaCardScanHandlerError.FailedToCreateDerivationPath.errorDescription),
                ),
            )
            return
        }

        val derivationTask = DeriveWalletPublicKeyTask(wallet.publicKey, derivationPath)
        derivationTask.run(session) { result ->
            handleDerivationResponse(result, session, callback)
        }
    }

    private fun handleDerivationResponse(
        result: CompletionResult<ExtendedPublicKey>,
        session: CardSession,
        callback: (result: CompletionResult<VisaCardActivationStatus>) -> Unit,
    ) {
        when (result) {
            is CompletionResult.Success -> {
                Timber.i("Start task for loading challenge for Visa wallet")
                handleWalletAuthorization(session, callback)
            }
            is CompletionResult.Failure -> {
                callback(CompletionResult.Failure(result.error))
            }
        }
    }

    private fun handleWalletAuthorization(
        session: CardSession,
        callback: (result: CompletionResult<VisaCardActivationStatus>) -> Unit,
    ) {
        Timber.i("Started handling authorization using Visa wallet")
        val card = session.environment.card ?: run {
            callback(CompletionResult.Failure(TangemSdkError.MissingPreflightRead()))
            return
        }

        val derivationPath = VisaUtilities.visaDefaultDerivationPath ?: run {
            Timber.e("Failed to create derivation path while handling wallet authorization")
            callback(
                CompletionResult.Failure(
                    TangemSdkError.Underlying(VisaCardScanHandlerError.FailedToCreateDerivationPath.errorDescription),
                ),
            )
            return
        }

        val wallet = card.wallets.firstOrNull { it.curve == VisaUtilities.mandatoryCurve } ?: run {
            Timber.e("Failed to find extended public key while handling wallet authorization")
            callback(
                CompletionResult.Failure(
                    TangemSdkError.Underlying(VisaCardScanHandlerError.FailedToFindDerivedWalletKey.errorDescription),
                ),
            )
            return
        }

        val extendedPublicKey = wallet.derivedKeys[derivationPath] ?: run {
            Timber.e("Failed to find extended public key while handling wallet authorization")
            callback(
                CompletionResult.Failure(
                    TangemSdkError.Underlying(VisaCardScanHandlerError.FailedToFindDerivedWalletKey.errorDescription),
                ),
            )
            return
        }

        Timber.i("Requesting challenge for wallet authorization")
        coroutineScope.launch {
            // Will be changed later after backend implementation
            val challengeResponse = runCatching {
                visaAuthRepository.getCustomerWalletAuthChallenge(
                    cardId = card.cardId,
                    walletPublicKey = extendedPublicKey.publicKey.toHexString(),
                )
            }.getOrElse {
                callback(
                    CompletionResult.Failure(TangemSdkError.Underlying(it.message ?: "Unknown error")),
                )
                return@launch
            }

            signChallengeWithWallet(
                publicKey = wallet.publicKey,
                derivationPath = derivationPath,
                nonce = challengeResponse.challenge,
                session = session,
            ) { result ->
                when (result) {
                    is CompletionResult.Success -> {
                        Timber.i("Challenge signed with Wallet public key")
                        handleWalletAuthorizationTokens(
                            session = session,
                            signedChallenge = challengeResponse.toSignedChallenge(result.data.signature.toHexString()),
                            callback = callback,
                        )
                    }
                    is CompletionResult.Failure -> {
                        Timber.e("Error during Wallet authorization process. Tangem Sdk Error: ${result.error}")
                        callback(CompletionResult.Failure(result.error))
                    }
                }
            }
        }
    }

    private fun handleWalletAuthorizationTokens(
        session: CardSession,
        signedChallenge: VisaAuthSignedChallenge,
        callback: (result: CompletionResult<VisaCardActivationStatus>) -> Unit,
    ) {
        coroutineScope.launch {
            val authorizationTokensResponse = runCatching {
                visaAuthRepository.getAccessTokens(signedChallenge = signedChallenge)
            }.getOrElse {
                Timber.i(
                    "Failed to get Access token for Wallet public key authoziation. Authorizing using Card Pub key",
                )
                handleCardAuthorization(session, callback)
                return@launch
            }

            Timber.i("Authorized using Wallet public key successfully")

            callback(CompletionResult.Success(VisaCardActivationStatus.Activated(authorizationTokensResponse)))
        }
    }

    private suspend fun handleCardAuthorization(
        session: CardSession,
        callback: (result: CompletionResult<VisaCardActivationStatus>) -> Unit,
    ) {
        val card = session.environment.card ?: run {
            callback(CompletionResult.Failure(TangemSdkError.MissingPreflightRead()))
            return
        }

        Timber.i("Requesting authorization challenge to sign")

        val challengeResponse = runCatching {
            visaAuthRepository.getCardAuthChallenge(
                cardId = card.cardId,
                cardPublicKey = card.cardPublicKey.toHexString(),
            )
        }.getOrElse {
            Timber.e("Failed to get challenge for Card authorization. Plain error: ${it.message}")
            callback(CompletionResult.Failure(TangemSdkError.Underlying(it.message ?: "Unknown error")))
            return
        }

        Timber.i("Received challenge to sign: ${challengeResponse.challenge}")

        signChallengeWithCard(session = session, challenge = challengeResponse.challenge) { result ->
            val attestCardKeyResponse = when (result) {
                is CompletionResult.Success -> {
                    Timber.i("Challenged signed.")
                    result.data
                }
                is CompletionResult.Failure -> {
                    Timber.e("Failed to sign challenge with Card public key. Tangem Sdk Error: ${result.error}")
                    callback(CompletionResult.Failure(result.error))
                    return@signChallengeWithCard
                }
            }

            coroutineScope.launch {
                @Suppress("UnusedPrivateMember")
                val authorizationTokensResponse = runCatching {
                    visaAuthRepository.getAccessTokens(
                        signedChallenge = challengeResponse.toSignedChallenge(
                            signedChallenge = attestCardKeyResponse.cardSignature.toHexString(),
                            salt = attestCardKeyResponse.salt.toHexString(),
                        ),
                    )
                }.getOrElse {
                    Timber.e("Failed to sign challenge with Card public key. Plain error: ${it.message}")
                    callback(
                        CompletionResult.Failure(
                            TangemSdkError.Underlying(
                                customMessage = it.message ?: "Unknown error",
                            ),
                        ),
                    )
                    return@launch
                }

                TODO() // implement card activation status handling (AND-9497)
            }
        }
    }

    private fun signChallengeWithWallet(
        publicKey: ByteArray,
        derivationPath: DerivationPath,
        nonce: String,
        session: CardSession,
        callback: (result: CompletionResult<SignHashResponse>) -> Unit,
    ) {
        val signHashCommand = SignHashCommand(publicKey, nonce.toByteArray(), derivationPath)
        signHashCommand.run(session) { result ->
            when (result) {
                is CompletionResult.Success -> {
                    callback(CompletionResult.Success(result.data))
                }
                is CompletionResult.Failure -> {
                    callback(CompletionResult.Failure(result.error))
                }
            }
        }
    }

    private fun signChallengeWithCard(
        session: CardSession,
        challenge: String,
        callback: (result: CompletionResult<AttestCardKeyResponse>) -> Unit,
    ) {
        val signHashCommand = AttestCardKeyCommand(challenge = challenge.toByteArray())
        signHashCommand.run(session) { result ->
            when (result) {
                is CompletionResult.Success -> {
                    callback(CompletionResult.Success(result.data))
                }
                is CompletionResult.Failure -> {
                    callback(CompletionResult.Failure(result.error))
                }
            }
        }
    }
}
