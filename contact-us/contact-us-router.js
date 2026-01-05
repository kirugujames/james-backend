import express from "express";
import { submitContact, getAllContacts } from "./contact-us-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();

/**
 * @swagger
 * /api/contact/submit:
 *   post:
 *     summary: Submit a contact form
 *     description: Public endpoint to submit a contact inquiry.
 *     tags: [Contact]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - message
 *             properties:
 *               name:
 *                 type: string
 *                 example: "John Doe"
 *               email:
 *                 type: string
 *                 example: "john@example.com"
 *               message:
 *                 type: string
 *                 example: "I would like more information about your services."
 *     responses:
 *       200:
 *         description: Contact submitted successfully
 *       400:
 *         description: Validation error
 */
// Public
router.post("/submit", auditMiddleware("CONTACT_SUBMIT"), async (req, res) => {
    const result = await submitContact(req);
    return res.status(result.statusCode).json(result);
});

// Admin
/**
 * @swagger
 * /api/contact/all:
 *   get:
 *     summary: Retrieve all contact submissions
 *     description: Admin endpoint to fetch all contact inquiries.
 *     tags: [Contact]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of contact submissions
 *       401:
 *         description: Unauthorized
 */
router.get("/all", verifyToken, async (req, res) => {
    const result = await getAllContacts();
    return res.status(result.statusCode).json(result);
});

export default router;
