package com.tangem.domain.visa.model

enum class VisaActivationRemoteState {
    CardWalletSignatureRequired,
    CustomerWalletSignatureRequired,
    PaymentAccountDeploying,
    WaitingPinCode,
    WaitingForActivationFinishing,
    Activated,
    BlockedForActivation,
}
