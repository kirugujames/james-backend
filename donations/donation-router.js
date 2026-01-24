import express from "express";
import {
    createIndividualDonation,
    updateIndividualDonation,
    getIndividualDonations,
    createOrganizationDonation,
    updateOrganizationDonation,
    getOrganizationDonations
} from "./donation-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();

/**
 * @swagger
 * /api/donations/individual/create:
 *   post:
 *     summary: Create an individual donation
 *     tags: [Donations]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               amount:
 *                 type: number
 *               firstname:
 *                 type: string
 *               lastname:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               is_anonymous:
 *                 type: boolean
 *     responses:
 *       201:
 *         description: Created successfully
 */
router.post("/individual/create", async (req, res) => {
    const result = await createIndividualDonation(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/donations/individual/update/{id}:
 *   patch:
 *     summary: Update an individual donation
 *     tags: [Donations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               amount:
 *                 type: number
 *               firstname:
 *                 type: string
 *               lastname:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               is_anonymous:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Updated successfully
 */
router.patch("/individual/update/:id", verifyToken, async (req, res) => {
    const result = await updateIndividualDonation(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/donations/individual/all:
 *   get:
 *     summary: Get all individual donations
 *     tags: [Donations]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of individual donations
 */
router.get("/individual/all", verifyToken, async (req, res) => {
    const result = await getIndividualDonations();
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/donations/organization/create:
 *   post:
 *     summary: Create an organization donation
 *     tags: [Donations]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               amount:
 *                 type: number
 *               organization_name:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               is_anonymous:
 *                 type: boolean
 *     responses:
 *       201:
 *         description: Created successfully
 */
router.post("/organization/create", async (req, res) => {
    const result = await createOrganizationDonation(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/donations/organization/update/{id}:
 *   patch:
 *     summary: Update an organization donation
 *     tags: [Donations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               amount:
 *                 type: number
 *               organization_name:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               is_anonymous:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Updated successfully
 */
router.patch("/organization/update/:id", verifyToken, async (req, res) => {
    const result = await updateOrganizationDonation(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/donations/organization/all:
 *   get:
 *     summary: Get all organization donations
 *     tags: [Donations]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of organization donations
 */
router.get("/organization/all", verifyToken, async (req, res) => {
    const result = await getOrganizationDonations();
    return res.status(result.statusCode).json(result);
});

export default router;
