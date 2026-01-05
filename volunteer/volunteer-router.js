import express from "express";
import { signUpVolunteer, getAllVolunteers, getVolunteersByEvent } from "./volunteer-controller.js";
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
 *               - name
 *               - email
 *               - event_id
 *             properties:
 *               name:
 *                 type: string
 *                 example: "Jane Doe"
 *               email:
 *                 type: string
 *                 example: "jane@example.com"
 *               event_id:
 *                 type: integer
 *                 example: 5
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

export default router;
