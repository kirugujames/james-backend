import express from "express";
import { createApplication, getAllApplications, updateApplicationStatus } from "./political-app-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();

/**
 * @swagger
 * /api/political-applications/apply:
 *   post:
 *     summary: Submit a political application
 *     description: Allows a user to apply for a political position.
 *     tags: [Political Applications]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *               - position
 *             properties:
 *               userId:
 *                 type: integer
 *                 example: 12
 *               position:
 *                 type: string
 *                 example: "Mayor"
 *     responses:
 *       200:
 *         description: Application submitted successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */

// User restricted
router.post("/apply", verifyToken, auditMiddleware("POLITICAL_APPLY"), async (req, res) => {
    const result = await createApplication(req);
    return res.status(result.statusCode).json(result);
});

// Admin only
/**
 * @swagger
 * /api/political-applications/all:
 *   get:
 *     summary: Get all political applications
 *     description: Admin endpoint to retrieve all applications.
 *     tags: [Political Applications]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of applications
 *       401:
 *         description: Unauthorized
 */
router.get("/all", verifyToken, async (req, res) => {
    const result = await getAllApplications();
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/political-applications/status:
 *   patch:
 *     summary: Update application status
 *     description: Admin can approve or reject an application.
 *     tags: [Political Applications]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - applicationId
 *               - status
 *             properties:
 *               applicationId:
 *                 type: integer
 *                 example: 5
 *               status:
 *                 type: string
 *                 example: "approved"
 *     responses:
 *       200:
 *         description: Status updated
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.patch("/status", verifyToken, auditMiddleware("POLITICAL_APP_STATUS_UPDATE"), async (req, res) => {
    const result = await updateApplicationStatus(req);
    return res.status(result.statusCode).json(result);
});

export default router;
