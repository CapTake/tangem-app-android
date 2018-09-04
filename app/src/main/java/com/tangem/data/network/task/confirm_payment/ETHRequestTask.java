package com.tangem.data.network.task.confirm_payment;

import android.app.Activity;
import android.util.Log;
import android.view.View;

import com.tangem.data.network.request.InfuraRequest;
import com.tangem.data.network.task.InfuraTask;
import com.tangem.domain.wallet.Blockchain;
import com.tangem.presentation.activity.ConfirmPaymentActivity;

import org.json.JSONException;

import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.util.Date;
import java.util.List;

public class ETHRequestTask extends InfuraTask {
    private WeakReference<ConfirmPaymentActivity> reference;

    public ETHRequestTask(ConfirmPaymentActivity context, Blockchain blockchain) {
        super(blockchain);
        reference = new WeakReference<>(context);
    }

    @Override
    protected void onPostExecute(List<InfuraRequest> requests) {
        super.onPostExecute(requests);
        ConfirmPaymentActivity confirmPaymentActivity = reference.get();

        for (InfuraRequest request : requests) {
            try {
                Long price = 0L;
                if (request.error == null) {

                    if (request.isMethod(InfuraRequest.METHOD_ETH_GetGasPrice)) {
                        try {
                            String gasPrice = request.getResultString();
                            Log.i("sjjoefeff", gasPrice);
                            gasPrice = gasPrice.substring(2);
                            BigInteger l = new BigInteger(gasPrice, 16);


                            Log.i("sjjoefeff", gasPrice);

                            BigInteger m = confirmPaymentActivity.getCard().getBlockchain() == Blockchain.Token ? BigInteger.valueOf(55000) : BigInteger.valueOf(21000);
                            l = l.multiply(m);
                            String feeInGwei = confirmPaymentActivity.getCard().getAmountInGwei(String.valueOf(l));

                            Log.i("sjjoefeff", feeInGwei);

                            confirmPaymentActivity.setMinFee(feeInGwei);
                            confirmPaymentActivity.setMaxFee(feeInGwei);
                            confirmPaymentActivity.setNormalFee(feeInGwei);
                            confirmPaymentActivity.getEtFee().setText(feeInGwei);
                            confirmPaymentActivity.getEtFee().setError(null);
                            confirmPaymentActivity.getBtnSend().setVisibility(View.VISIBLE);
                            confirmPaymentActivity.setFeeRequestSuccess(true);
                            confirmPaymentActivity.setBalanceRequestSuccess(true);
                            confirmPaymentActivity.setDtVerified(new Date());
                            confirmPaymentActivity.setMinFeeInInternalUnits(confirmPaymentActivity.getCard().internalUnitsFromString(feeInGwei));

                        } catch (JSONException e) {
                            e.printStackTrace();
                            confirmPaymentActivity.finishActivityWithError(Activity.RESULT_CANCELED, "Can't calculate fee! No connection with blockchain nodes");
                        }
                    }
                } else {
                    confirmPaymentActivity.finishActivityWithError(Activity.RESULT_CANCELED, "Can't calculate fee! No connection with blockchain nodes");
                }
            } catch (JSONException e) {
                e.printStackTrace();
                confirmPaymentActivity.finishActivityWithError(Activity.RESULT_CANCELED, "Can't calculate fee! No connection with blockchain nodes");
            }
        }
    }

}