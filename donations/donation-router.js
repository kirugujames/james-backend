import express from "express";
import { createElectronicDonation, createCashDonation, getAllDonations } from "./donation-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();

/**
 * @swagger
 * /api/donations/electronic:
 *   post:
 *     summary: Create an electronic donation
 *     description: Public endpoint to record an electronic donation.
 *     tags: [Donations]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - donorName
 *               - amount
 *               - paymentMethod
 *             properties:
 *               donorName:
 *                 type: string
 *                 example: "John Doe"
 *               amount:
 *                 type: number
 *                 example: 150.00
 *               paymentMethod:
 *                 type: string
 *                 example: "credit_card"
 *     responses:
 *       200:
 *         description: Donation recorded successfully
 *       400:
 *         description: Validation error
 */

// Public link or secured depending on UI
router.post("/electronic", auditMiddleware("DONATION_ELECTRONIC"), async (req, res) => {
    const result = await createElectronicDonation(req);
    return res.status(result.statusCode).json(result);
});

// Admin only
/**
 * @swagger
 * /api/donations/cash:
 *   post:
 *     summary: Record a cash donation
 *     description: Admin endpoint to record a manual cash donation.
 *     tags: [Donations]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - donorName
 *               - amount
 *             properties:
 *               donorName:
 *                 type: string
 *                 example: "Jane Smith"
 *               amount:
 *                 type: number
 *                 example: 200.00
 *     responses:
 *       200:
 *         description: Cash donation recorded successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.post("/cash", verifyToken, auditMiddleware("DONATION_CASH"), async (req, res) => {
    const result = await createCashDonation(req);
    return res.status(result.statusCode).json(result);
});

// Admin only
/**
 * @swagger
 * /api/donations/all:
 *   get:
 *     summary: Retrieve all donations
 *     description: Admin endpoint to fetch all donation records.
 *     tags: [Donations]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of donations retrieved successfully
 *       401:
 *         description: Unauthorized
 */
router.get("/all", verifyToken, async (req, res) => {
    const result = await getAllDonations();
    return res.status(result.statusCode).json(result);
});

export default router;
