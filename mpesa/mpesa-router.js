import express from "express";
import {
    initiateMpesaPayment,
    handleMpesaCallback,
    getPaymentStatus,
    getAllPayments,
} from "./mpesa-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();

/**
 * @swagger
 * /api/mpesa/stk-push:
 *   post:
 *     summary: Initiate M-Pesa STK push
 *     description: Send an STK push notification to a customer's phone to request payment
 *     tags: [M-Pesa]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - phoneNumber
 *               - amount
 *             properties:
 *               phoneNumber:
 *                 type: string
 *                 description: Customer phone number (254XXXXXXXXX, 07XXXXXXXX, or +254XXXXXXXXX)
 *                 example: "254712345678"
 *               amount:
 *                 type: number
 *                 description: Amount to charge in KES
 *                 example: 100
 *               accountReference:
 *                 type: string
 *                 description: Account reference for the transaction
 *                 example: "Invoice12345"
 *               transactionDesc:
 *                 type: string
 *                 description: Description of the transaction
 *                 example: "Payment for services"
 *     responses:
 *       200:
 *         description: STK push initiated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *                 message:
 *                   type: string
 *                   example: "STK push initiated successfully. Please check your phone."
 *                 data:
 *                   type: object
 *                   properties:
 *                     CheckoutRequestID:
 *                       type: string
 *                     MerchantRequestID:
 *                       type: string
 *       400:
 *         description: Validation error
 *       500:
 *         description: Server error
 */
router.post("/stk-push", auditMiddleware("MPESA_STK_PUSH_INIT"), async (req, res) => {
    const result = await initiateMpesaPayment(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/mpesa/callback:
 *   post:
 *     summary: M-Pesa callback endpoint
 *     description: Receives payment status updates from Safaricom (internal use only)
 *     tags: [M-Pesa]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Callback processed successfully
 */
router.post("/callback", async (req, res) => {
    const result = await handleMpesaCallback(req);

    // M-Pesa expects a simple acknowledgment
    return res.status(200).json({
        ResultCode: 0,
        ResultDesc: "Success",
    });
});

/**
 * @swagger
 * /api/mpesa/payment/{checkoutRequestId}:
 *   get:
 *     summary: Get payment status
 *     description: Retrieve the status of a specific M-Pesa payment by CheckoutRequestID
 *     tags: [M-Pesa]
 *     parameters:
 *       - in: path
 *         name: checkoutRequestId
 *         required: true
 *         schema:
 *           type: string
 *         description: The CheckoutRequestID returned when initiating the payment
 *     responses:
 *       200:
 *         description: Payment status retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     phone_number:
 *                       type: string
 *                     amount:
 *                       type: number
 *                     status:
 *                       type: string
 *                       enum: [pending, completed, failed, cancelled]
 *                     mpesa_receipt_number:
 *                       type: string
 *       404:
 *         description: Payment not found
 */
router.get("/payment/:checkoutRequestId", async (req, res) => {
    const result = await getPaymentStatus(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/mpesa/all:
 *   get:
 *     summary: Get all M-Pesa payments
 *     description: Admin endpoint to retrieve all M-Pesa payment records
 *     tags: [M-Pesa]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Payments retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *                 message:
 *                   type: string
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *       401:
 *         description: Unauthorized
 */
router.get("/all", verifyToken, async (req, res) => {
    const result = await getAllPayments();
    return res.status(result.statusCode).json(result);
});

export default router;
