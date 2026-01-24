import express from "express";
import { body, validationResult } from "express-validator";
import {
    applyForAspirant,
    getAllAspirantApplications,
    getAspirantApplicationsByMember,
    updateAspirantStatus
} from "./aspirant-controller.js";
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
 *   name: Aspirants
 *   description: Aspirant position applications
 */

/**
 * @swagger
 * /api/aspirants/apply:
 *   post:
 *     summary: Apply for an aspirant position
 *     tags: [Aspirants]
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
router.post("/apply", verifyToken, auditMiddleware("ASPIRANT_APPLY"), validateApplication, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const result = await applyForAspirant(req);
    return res.status(result.statusCode).send(result);
});

/**
 * @swagger
 * /api/aspirants/all:
 *   get:
 *     summary: Get all aspirant applications
 *     tags: [Aspirants]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of applications
 */
router.get("/all", verifyToken, async (req, res) => {
    const result = await getAllAspirantApplications();
    return res.status(result.statusCode).send(result);
});

/**
 * @swagger
 * /api/aspirants/member/{identifier}:
 *   get:
 *     summary: Get applications by membership number
 *     tags: [Aspirants]
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
    const result = await getAspirantApplicationsByMember(req.params.identifier);
    return res.status(result.statusCode).send(result);
});

/**
 * @swagger
 * /api/aspirants/update-status:
 *   patch:
 *     summary: Update application status
 *     tags: [Aspirants]
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
 *                 example: "Does not meet residency requirements"
 *     responses:
 *       200:
 *         description: Status updated
 */
router.patch("/update-status", verifyToken, auditMiddleware("ASPIRANT_STATUS_UPDATE"), validateStatusUpdate, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const result = await updateAspirantStatus(req);
    return res.status(result.statusCode).send(result);
});

export default router;
