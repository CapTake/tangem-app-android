package com.tangem.domain.visa.model

sealed class VisaCardActivationStatus {

    data class Activated(val visaAuthTokens: VisaAuthTokens) : VisaCardActivationStatus()

    data class NotStartedActivation(val activationInput: VisaActivationInput) : VisaCardActivationStatus()

    data object Blocked : VisaCardActivationStatus()
}
