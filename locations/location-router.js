import express from "express";
import {
    getAllCounties,
    getSubcountiesByCounty,
    getWardsBySubcounty,
    bulkInsertCounties,
    bulkInsertSubcounties,
    bulkInsertWards,
} from "./location-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();

/**
 * @swagger
 * /api/locations/counties:
 *   get:
 *     summary: Get all counties
 *     description: Retrieve a list of all counties in Kenya
 *     tags: [Locations]
 *     responses:
 *       200:
 *         description: Counties fetched successfully
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
 *                       name:
 *                         type: string
 *                       code:
 *                         type: string
 */
router.get("/counties", async (req, res) => {
    const result = await getAllCounties();
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/locations/counties/{countyId}/subcounties:
 *   get:
 *     summary: Get subcounties by county ID
 *     description: Retrieve all subcounties for a specific county
 *     tags: [Locations]
 *     parameters:
 *       - in: path
 *         name: countyId
 *         required: true
 *         schema:
 *           type: integer
 *         description: The county ID
 *     responses:
 *       200:
 *         description: Subcounties fetched successfully
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
 *                       name:
 *                         type: string
 *                       county_id:
 *                         type: integer
 *       404:
 *         description: County not found
 */
router.get("/counties/:countyId/subcounties", async (req, res) => {
    const result = await getSubcountiesByCounty(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/locations/subcounties/{subcountyId}/wards:
 *   get:
 *     summary: Get wards by subcounty ID
 *     description: Retrieve all wards for a specific subcounty
 *     tags: [Locations]
 *     parameters:
 *       - in: path
 *         name: subcountyId
 *         required: true
 *         schema:
 *           type: integer
 *         description: The subcounty ID
 *     responses:
 *       200:
 *         description: Wards fetched successfully
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
 *                       name:
 *                         type: string
 *                       subcounty_id:
 *                         type: integer
 *       404:
 *         description: Subcounty not found
 */
router.get("/subcounties/:subcountyId/wards", async (req, res) => {
    const result = await getWardsBySubcounty(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/locations/counties/bulk:
 *   post:
 *     summary: Bulk insert counties
 *     description: Admin endpoint to insert multiple counties at once
 *     tags: [Locations]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - counties
 *             properties:
 *               counties:
 *                 type: array
 *                 items:
 *                   type: object
 *                   required:
 *                     - name
 *                   properties:
 *                     name:
 *                       type: string
 *                       example: "Nairobi"
 *                     code:
 *                       type: string
 *                       example: "001"
 *     responses:
 *       201:
 *         description: Counties inserted successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.post("/counties/bulk", verifyToken, auditMiddleware("LOCATION_COUNTIES_BULK"), async (req, res) => {
    const result = await bulkInsertCounties(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/locations/subcounties/bulk:
 *   post:
 *     summary: Bulk insert subcounties
 *     description: Admin endpoint to insert multiple subcounties at once
 *     tags: [Locations]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - subcounties
 *             properties:
 *               subcounties:
 *                 type: array
 *                 items:
 *                   type: object
 *                   required:
 *                     - name
 *                     - county_id
 *                   properties:
 *                     name:
 *                       type: string
 *                       example: "Westlands"
 *                     county_id:
 *                       type: integer
 *                       example: 1
 *     responses:
 *       201:
 *         description: Subcounties inserted successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.post("/subcounties/bulk", verifyToken, auditMiddleware("LOCATION_SUBCOUNTIES_BULK"), async (req, res) => {
    const result = await bulkInsertSubcounties(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/locations/wards/bulk:
 *   post:
 *     summary: Bulk insert wards
 *     description: Admin endpoint to insert multiple wards at once
 *     tags: [Locations]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - wards
 *             properties:
 *               wards:
 *                 type: array
 *                 items:
 *                   type: object
 *                   required:
 *                     - name
 *                     - subcounty_id
 *                   properties:
 *                     name:
 *                       type: string
 *                       example: "Parklands"
 *                     subcounty_id:
 *                       type: integer
 *                       example: 1
 *     responses:
 *       201:
 *         description: Wards inserted successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.post("/wards/bulk", verifyToken, auditMiddleware("LOCATION_WARDS_BULK"), async (req, res) => {
    const result = await bulkInsertWards(req);
    return res.status(result.statusCode).json(result);
});

export default router;
