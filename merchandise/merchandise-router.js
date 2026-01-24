import express from "express";
import { createMerch, getAllMerch, updateMerch, deleteMerch } from "./merchandise-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Merchandise
 *   description: APIs for managing party merchandise and shop items
 */

/**
 * @swagger
 * /api/merchandise/all:
 *   get:
 *     summary: Get all merchandise items
 *     tags: [Merchandise]
 *     responses:
 *       200:
 *         description: List of merchandise items
 */
router.get("/all", async (req, res) => {
    const result = await getAllMerch();
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/merchandise/add:
 *   post:
 *     summary: Add new merchandise
 *     tags: [Merchandise]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - price
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               price:
 *                 type: number
 *               stock:
 *                 type: integer
 *               category:
 *                 type: string
 *               size:
 *                 type: array
 *                 items:
 *                   type: string
 *               image:
 *                 type: string
 *                 description: Base64 encoded image string
 *               status:
 *                 type: string
 *                 example: ACTIVE
 *     responses:
 *       200:
 *         description: Merchandise added
 */
router.post("/add", verifyToken, auditMiddleware("MERCH_ADD"), async (req, res) => {
    const result = await createMerch(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/merchandise/update/{id}:
 *   patch:
 *     summary: Update merchandise
 *     tags: [Merchandise]
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
 *               name:
 *                 type: string
 *               price:
 *                 type: number
 *               stock:
 *                 type: integer
 *               category:
 *                 type: string
 *               size:
 *                 type: array
 *                 items:
 *                   type: string
 *               image:
 *                 type: string
 *                 description: Base64 encoded image string
 *               status:
 *                 type: string
 *                 example: ACTIVE
 *     responses:
 *       200:
 *         description: Updated successfully
 */
router.patch("/update/:id", verifyToken, auditMiddleware("MERCH_UPDATE"), async (req, res) => {
    const result = await updateMerch(req);
    return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/merchandise/delete/{id}:
 *   delete:
 *     summary: Delete merchandise
 *     tags: [Merchandise]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Deleted successfully
 */
router.delete("/delete/:id", verifyToken, auditMiddleware("MERCH_DELETE"), async (req, res) => {
    const result = await deleteMerch(req);
    return res.status(result.statusCode).json(result);
});

export default router;
