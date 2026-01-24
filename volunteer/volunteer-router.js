import express from "express";
import { signUpVolunteer, getAllVolunteers, getVolunteersByEvent, updateVolunteerStatus } from "./volunteer-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();

/**
 * @swagger
 * /api/volunteers/signup:
 *   post:
 *     summary: Volunteer sign‑up
 *     description: Public endpoint for a user to register as a volunteer for events.
 *     tags: [Volunteer]
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
 *               - volunteer_type
 *               - phone
 *               - consent
 *             properties:
 *               first_name:
 *                 type: string
 *                 example: "Jane"
 *               last_name:
 *                 type: string
 *                 example: "Doe"
 *               email:
 *                 type: string
 *                 example: "jane@example.com"
 *               phone:
 *                 type: string
 *                 example: "0712345678"
 *               volunteer_type:
 *                 type: string
 *                 enum: [general, event]
 *                 example: "event"
 *               event_id:
 *                 type: integer
 *                 example: 1
 *               event_name:
 *                 type: string
 *                 example: "Community Cleanup"
 *               areas_of_interest:
 *                 type: array
 *                 items:
 *                   type: string
 *                 example: ["Logistics", "Communication"]
 *               consent:
 *                 type: boolean
 *                 example: true
 *     responses:
 *       200:
 *         description: Volunteer signed up successfully
 *       400:
 *         description: Validation error
 */
// Public
router.post("/signup", auditMiddleware("VOLUNTEER_SIGNUP"), async (req, res) => {
    const result = await signUpVolunteer(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/volunteers/all:
 *   get:
 *     summary: Get all volunteers
 *     description: Admin endpoint to retrieve all volunteer records.
 *     tags: [Volunteer]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of volunteers
 *       401:
 *         description: Unauthorized
 */
// Admin
router.get("/all", verifyToken, async (req, res) => {
    const result = await getAllVolunteers();
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/volunteers/event/{event_id}:
 *   get:
 *     summary: Get volunteers for an event
 *     description: Admin endpoint to fetch volunteers associated with a specific event.
 *     tags: [Volunteer]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: event_id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the event
 *     responses:
 *       200:
 *         description: List of volunteers for the event
 *       401:
 *         description: Unauthorized
 */
router.get("/event/:event_id", verifyToken, async (req, res) => {
    const result = await getVolunteersByEvent(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/volunteers/update-status:
 *   patch:
 *     summary: Update volunteer status
 *     tags: [Volunteer]
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
 *                 enum: [pending, approved, rejected]
 *               reason:
 *                 type: string
 *                 description: Optional reason for rejection
 *     responses:
 *       200:
 *         description: Status updated
 */
router.patch("/update-status", verifyToken, auditMiddleware("VOLUNTEER_STATUS_UPDATE"), async (req, res) => {
    const result = await updateVolunteerStatus(req);
    return res.status(result.statusCode).json(result);
});

export default router;
