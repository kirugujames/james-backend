import express from "express";
import { body, validationResult } from "express-validator";
import {
    applyForPartyPosition,
    getAllPartyPositionApplications,
    getPartyPositionApplicationsByMember,
    updatePartyPositionStatus
} from "./party-position-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();

// Validation rules
const validateApplication = [
    body("first_name").notEmpty().withMessage("First name is required"),
    body("last_name").notEmpty().withMessage("Last name is required"),
    body("email").isEmail().withMessage("Valid email is required"),
    body("phone").notEmpty().withMessage("Phone number is required"),
    body("membership_number").notEmpty().withMessage("Membership number is required"),
    body("position").notEmpty().withMessage("Position is required"),
];

const validateStatusUpdate = [
    body("id").notEmpty().withMessage("Application ID is required"),
    body("status").notEmpty().withMessage("Status is required").isIn(["Pending", "Approved", "Rejected", "Under Review"]).withMessage("Invalid status value"),
];

/**
 * @swagger
 * tags:
 *   name: Party Positions
 *   description: Party position applications
 */

/**
 * @swagger
 * /api/party-positions/apply:
 *   post:
 *     summary: Apply for a party position
 *     tags: [Party Positions]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - first_name
 *               - last_name
 *               - email
 *               - phone
 *               - membership_number
 *               - position
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               membership_number:
 *                 type: string
 *               position:
 *                 type: string
 *     responses:
 *       201:
 *         description: Application submitted successfully
 */
router.post("/apply", verifyToken, auditMiddleware("PARTY_POSITION_APPLY"), validateApplication, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const result = await applyForPartyPosition(req);
    return res.status(result.statusCode).send(result);
});

/**
 * @swagger
 * /api/party-positions/all:
 *   get:
 *     summary: Get all party position applications
 *     tags: [Party Positions]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of applications
 */
router.get("/all", verifyToken, async (req, res) => {
    const result = await getAllPartyPositionApplications();
    return res.status(result.statusCode).send(result);
});

/**
 * @swagger
 * /api/party-positions/member/{identifier}:
 *   get:
 *     summary: Get applications by membership number
 *     tags: [Party Positions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: identifier
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of applications
 */
router.get("/member/:identifier", verifyToken, async (req, res) => {
    const result = await getPartyPositionApplicationsByMember(req.params.identifier);
    return res.status(result.statusCode).send(result);
});

/**
 * @swagger
 * /api/party-positions/update-status:
 *   patch:
 *     summary: Update application status
 *     tags: [Party Positions]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - id
 *               - status
 *             properties:
 *               id:
 *                 type: integer
 *               status:
 *                 type: string
 *                 enum: [Pending, Approved, Rejected, Under Review]
 *               reason:
 *                 type: string
 *                 description: Optional reason for rejection or status change
 *                 example: "Incomplete application"
 *     responses:
 *       200:
 *         description: Status updated
 */
router.patch("/update-status", verifyToken, auditMiddleware("PARTY_POSITION_STATUS_UPDATE"), validateStatusUpdate, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const result = await updatePartyPositionStatus(req);
    return res.status(result.statusCode).send(result);
});

export default router;
