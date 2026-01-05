import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

// M-Pesa API Configuration
const MPESA_ENVIRONMENT = process.env.MPESA_ENVIRONMENT || "sandbox";
const CONSUMER_KEY = process.env.MPESA_CONSUMER_KEY?.trim();
const CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET?.trim();
const BUSINESS_SHORT_CODE = process.env.MPESA_BUSINESS_SHORT_CODE?.trim();
const PASSKEY = process.env.MPESA_PASSKEY?.trim();
const CALLBACK_URL = process.env.MPESA_CALLBACK_URL?.trim();

// Validate configuration on module load
if (!CONSUMER_KEY || !CONSUMER_SECRET) {
    console.warn("⚠️  M-Pesa credentials not configured. Please check your .env file.");
}
if (!BUSINESS_SHORT_CODE || !PASSKEY) {
    console.warn("⚠️  M-Pesa business details not configured. Please check your .env file.");
}

// API URLs
const BASE_URL =
    MPESA_ENVIRONMENT === "production"
        ? "https://api.safaricom.co.ke"
        : "https://sandbox.safaricom.co.ke";

const AUTH_URL = `${BASE_URL}/oauth/v1/generate?grant_type=client_credentials`;
const STK_PUSH_URL = `${BASE_URL}/mpesa/stkpush/v1/processrequest`;

/**
 * Generate M-Pesa access token
 * @returns {Promise<string>} Access token
 */
export async function generateAccessToken() {
    try {
        // Validate credentials
        if (!CONSUMER_KEY || !CONSUMER_SECRET) {
            throw new Error("M-Pesa consumer key and secret must be configured in .env file");
        }

        const auth = Buffer.from(`${CONSUMER_KEY}:${CONSUMER_SECRET}`).toString("base64");

        console.log("🔐 Attempting M-Pesa authentication...");
        console.log("📍 Environment:", MPESA_ENVIRONMENT);
        console.log("🔗 Auth URL:", AUTH_URL);

        const response = await axios.get(AUTH_URL, {
            headers: {
                Authorization: `Basic ${auth}`,
            },
        });

        console.log("✅ M-Pesa access token generated successfully");
        return response.data.access_token;
    } catch (error) {
        console.error("❌ Error generating access token:");
        console.error("Status:", error.response?.status);
        console.error("Status Text:", error.response?.statusText);
        console.error("Error Data:", JSON.stringify(error.response?.data, null, 2));
        console.error("Request URL:", AUTH_URL);

        if (error.response?.status === 400) {
            throw new Error("Invalid M-Pesa credentials. Please verify MPESA_CONSUMER_KEY and MPESA_CONSUMER_SECRET in your .env file");
        }

        throw new Error(error.response?.data?.error_description || "Failed to generate M-Pesa access token");
    }
}

/**
 * Generate password for STK push
 * @returns {Object} Object containing password and timestamp
 */
export function generatePassword() {
    const timestamp = new Date()
        .toISOString()
        .replace(/[^0-9]/g, "")
        .slice(0, 14); // YYYYMMDDHHmmss format

    const password = Buffer.from(
        `${BUSINESS_SHORT_CODE}${PASSKEY}${timestamp}`
    ).toString("base64");

    return { password, timestamp };
}

/**
 * Initiate STK Push
 * @param {string} phoneNumber - Customer phone number (254XXXXXXXXX)
 * @param {number} amount - Amount to charge
 * @param {string} accountReference - Account reference
 * @param {string} transactionDesc - Transaction description
 * @returns {Promise<Object>} M-Pesa response
 */
export async function initiateSTKPush(phoneNumber, amount, accountReference, transactionDesc) {
    try {
        const accessToken = await generateAccessToken();
        const { password, timestamp } = generatePassword();

        // Format phone number to 254XXXXXXXXX
        let formattedPhone = phoneNumber;
        if (formattedPhone.startsWith("0")) {
            formattedPhone = "254" + formattedPhone.slice(1);
        } else if (formattedPhone.startsWith("+254")) {
            formattedPhone = formattedPhone.slice(1);
        } else if (!formattedPhone.startsWith("254")) {
            formattedPhone = "254" + formattedPhone;
        }

        const payload = {
            BusinessShortCode: BUSINESS_SHORT_CODE,
            Password: password,
            Timestamp: timestamp,
            TransactionType: "CustomerPayBillOnline",
            Amount: Math.round(amount), // M-Pesa requires integer
            PartyA: formattedPhone,
            PartyB: BUSINESS_SHORT_CODE,
            PhoneNumber: formattedPhone,
            CallBackURL: CALLBACK_URL,
            AccountReference: accountReference || "Payment",
            TransactionDesc: transactionDesc || "Payment",
        };

        const response = await axios.post(STK_PUSH_URL, payload, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": "application/json",
            },
        });

        return response.data;
    } catch (error) {
        console.error("Error initiating STK push:", error.response?.data || error.message);
        throw new Error(error.response?.data?.errorMessage || "Failed to initiate STK push");
    }
}
