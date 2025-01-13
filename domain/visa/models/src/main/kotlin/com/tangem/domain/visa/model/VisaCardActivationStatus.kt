package com.tangem.domain.visa.model

sealed class VisaCardActivationStatus {

    data class Activated(val visaAuthTokens: VisaAuthTokens) : VisaCardActivationStatus()

    data class ActivationStarted(
        val activationInput: VisaActivationInput,
        val authTokens: VisaAuthTokens,
        val remoteState: VisaActivationRemoteState,
    ) : VisaCardActivationStatus()

    data class NotStartedActivation(val activationInput: VisaActivationInput) : VisaCardActivationStatus()

    data object Blocked : VisaCardActivationStatus()
}
