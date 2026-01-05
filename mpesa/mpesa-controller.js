import MpesaPayment from "./Models/MpesaPayment.js";
import { initiateSTKPush } from "./mpesa-utils.js";

/**
 * Initiate M-Pesa payment
 * @param {Object} req - Express request object
 * @returns {Object} Response object
 */
export async function initiateMpesaPayment(req) {
    const { phoneNumber, amount, accountReference, transactionDesc } = req.body;

    // Validation
    if (!phoneNumber || !amount) {
        return {
            statusCode: 400,
            message: "Phone number and amount are required",
            data: null,
        };
    }

    if (amount <= 0) {
        return {
            statusCode: 400,
            message: "Amount must be greater than zero",
            data: null,
        };
    }

    // Validate phone number format
    const phoneRegex = /^(\+?254|0)?[17]\d{8}$/;
    if (!phoneRegex.test(phoneNumber)) {
        return {
            statusCode: 400,
            message: "Invalid phone number format. Use 254XXXXXXXXX, 07XXXXXXXX, or +254XXXXXXXXX",
            data: null,
        };
    }

    try {
        // Initiate STK push
        const mpesaResponse = await initiateSTKPush(
            phoneNumber,
            amount,
            accountReference,
            transactionDesc
        );

        // Save payment record
        const payment = await MpesaPayment.create({
            phone_number: phoneNumber,
            amount,
            account_reference: accountReference,
            transaction_desc: transactionDesc,
            merchant_request_id: mpesaResponse.MerchantRequestID,
            checkout_request_id: mpesaResponse.CheckoutRequestID,
            status: "pending",
        });

        return {
            statusCode: 200,
            message: "STK push initiated successfully. Please check your phone.",
            data: {
                CheckoutRequestID: mpesaResponse.CheckoutRequestID,
                MerchantRequestID: mpesaResponse.MerchantRequestID,
                ResponseDescription: mpesaResponse.ResponseDescription,
                CustomerMessage: mpesaResponse.CustomerMessage,
                payment,
            },
        };
    } catch (error) {
        console.error("Error initiating M-Pesa payment:", error);
        return {
            statusCode: 500,
            message: error.message || "Failed to initiate M-Pesa payment",
            data: null,
        };
    }
}

/**
 * Handle M-Pesa callback
 * @param {Object} req - Express request object
 * @returns {Object} Response object
 */
export async function handleMpesaCallback(req) {
    try {
        const { Body } = req.body;

        if (!Body || !Body.stkCallback) {
            return {
                statusCode: 400,
                message: "Invalid callback data",
                data: null,
            };
        }

        const {
            MerchantRequestID,
            CheckoutRequestID,
            ResultCode,
            ResultDesc,
        } = Body.stkCallback;

        // Find the payment record
        const payment = await MpesaPayment.findOne({
            where: { checkout_request_id: CheckoutRequestID },
        });

        if (!payment) {
            console.error(`Payment not found for CheckoutRequestID: ${CheckoutRequestID}`);
            return {
                statusCode: 404,
                message: "Payment record not found",
                data: null,
            };
        }

        // Update payment record
        const updateData = {
            result_code: String(ResultCode),
            result_desc: ResultDesc,
        };

        // ResultCode 0 means success
        if (ResultCode === 0) {
            updateData.status = "completed";

            // Extract callback metadata
            const callbackMetadata = Body.stkCallback.CallbackMetadata?.Item || [];

            callbackMetadata.forEach((item) => {
                if (item.Name === "MpesaReceiptNumber") {
                    updateData.mpesa_receipt_number = item.Value;
                }
                if (item.Name === "TransactionDate") {
                    // Convert from format 20210628092408 to Date
                    const dateStr = String(item.Value);
                    const year = dateStr.substring(0, 4);
                    const month = dateStr.substring(4, 6);
                    const day = dateStr.substring(6, 8);
                    const hour = dateStr.substring(8, 10);
                    const minute = dateStr.substring(10, 12);
                    const second = dateStr.substring(12, 14);
                    updateData.transaction_date = new Date(
                        `${year}-${month}-${day}T${hour}:${minute}:${second}`
                    );
                }
            });
        } else {
            // Payment failed or was cancelled
            updateData.status = ResultCode === 1032 ? "cancelled" : "failed";
        }

        await payment.update(updateData);

        console.log(`M-Pesa callback processed for CheckoutRequestID: ${CheckoutRequestID}`);

        return {
            statusCode: 200,
            message: "Callback processed successfully",
            data: payment,
        };
    } catch (error) {
        console.error("Error processing M-Pesa callback:", error);
        return {
            statusCode: 500,
            message: "Failed to process callback",
            data: null,
        };
    }
}

/**
 * Get payment status by CheckoutRequestID
 * @param {Object} req - Express request object
 * @returns {Object} Response object
 */
export async function getPaymentStatus(req) {
    const { checkoutRequestId } = req.params;

    try {
        const payment = await MpesaPayment.findOne({
            where: { checkout_request_id: checkoutRequestId },
        });

        if (!payment) {
            return {
                statusCode: 404,
                message: "Payment not found",
                data: null,
            };
        }

        return {
            statusCode: 200,
            message: "Payment status retrieved successfully",
            data: payment,
        };
    } catch (error) {
        console.error("Error fetching payment status:", error);
        return {
            statusCode: 500,
            message: "Failed to fetch payment status",
            data: null,
        };
    }
}

/**
 * Get all M-Pesa payments (Admin only)
 * @returns {Object} Response object
 */
export async function getAllPayments() {
    try {
        const payments = await MpesaPayment.findAll({
            order: [["createdAt", "DESC"]],
        });

        return {
            statusCode: 200,
            message: "Payments fetched successfully",
            data: payments,
        };
    } catch (error) {
        console.error("Error fetching payments:", error);
        return {
            statusCode: 500,
            message: "Failed to fetch payments",
            data: null,
        };
    }
}
