import express from "express";
import { getAllAuditTrails } from "./audit-trail-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";

const router = express.Router();

/**
 * @swagger
 * /api/audit/all:
 *   get:
 *     summary: Get all audit trails
 *     description: Retrieve a list of all audit trails (Admin only)
 *     tags: [Audit]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Audit trails fetched successfully
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
 *                     properties:
 *                       id:
 *                         type: integer
 *                       user_id:
 *                         type: integer
 *                       action:
 *                         type: string
 *                       details:
 *                         type: string
 *                       ip_address:
 *                         type: string
 *                       createdAt:
 *                         type: string
 *                         format: date-time
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
router.get("/all", verifyToken, async (req, res) => {
    const result = await getAllAuditTrails();
    return res.status(result.statusCode).json(result);
});

export default router;
