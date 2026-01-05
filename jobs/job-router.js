import express from "express";

/**
 * @swagger
 * /api/jobs/add:
 *   post:
 *     summary: Create a new job posting
 *     description: Allows an authenticated user to create a new job posting.
 *     tags: [Jobs]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - job_title
 *               - description
 *             properties:
 *               job_title:
 *                 type: string
 *                 example: "Frontend Developer"
 *               description:
 *                 type: string
 *                 example: "Develop and maintain web applications."
 *     responses:
 *       200:
 *         description: Job created successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
import { body, validationResult } from "express-validator";
import dotenv from "dotenv";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";
import { createJob, deleteJob, getAllJobs, getJobListingById, updateJobListing } from "./jobs-controller.js";

dotenv.config();

const router = express.Router();

// Validation rules
const validateJobCreation = [
  body("description").notEmpty().withMessage("description is required"),
  body("job_title").notEmpty().withMessage("job_title is required")
]

const validateJobUpdate = [
  body("id").notEmpty().withMessage("ID is required"),
  body("description").optional(),
  body("job_title").optional(),
  body("status").optional(),
]
/**
 * @swagger
 * /api/jobs/add:
 *   post:
 *     summary: Create a new job
 *     description: Allows an authenticated user to create a new job posting by providing job title and description.
 *     tags: [Job]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - job_title
 *               - description
 *             properties:
 *               job_title:
 *                 type: string
 *                 example: "Frontend Developer"
 *               description:
 *                 type: string
 *                 example: "Responsible for developing and maintaining the company’s web applications using React.js."
 *     responses:
 *       200:
 *         description: Job created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Job created successfully"
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                       example: 1
 *                     job_title:
 *                       type: string
 *                       example: "Frontend Developer"
 *                     description:
 *                       type: string
 *                       example: "Responsible for developing and maintaining the company’s web applications using React.js."
 *                     created_by:
 *                       type: string
 *                       example: "admin@company.com"
 *       400:
 *         description: Bad request — missing required fields
 *       401:
 *         description: Unauthorized — invalid or missing token
 *       500:
 *         description: Internal server error
 */
router.post("/add", validateJobCreation, verifyToken, auditMiddleware("JOB_CREATE"), async (req, res) => {
  const error = validationResult(req);
  if (!error.isEmpty()) {
    return res.status(400).json({
      message: "Missing or invalid fields",
      data: error.array(),
      statusCode: 400,
    });
  }
  const result = await createJob(req);
  return res.send(result);
});

/**
 * @swagger
 * /api/jobs/all:
 *   get:
 *     summary: Get all job postings
 *     description: Retrieves a list of all job postings in the system.
 *     tags: [Job]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully retrieved all jobs
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "success"
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 1
 *                       job_title:
 *                         type: string
 *                         example: "Frontend Developer"
 *                       description:
 *                         type: string
 *                         example: "Responsible for developing and maintaining the company’s web applications using React.js."
 *                       created_by:
 *                         type: string
 *                         example: "admin@company.com"
 *                       created_at:
 *                         type: string
 *                         format: date-time
 *                         example: "2025-11-07T18:30:00Z"
 *       401:
 *         description: Unauthorized — invalid or missing token
 *       500:
 *         description: Internal server error
 */
/**
 * @swagger
 * /api/jobs/all:
 *   get:
 *     summary: Retrieve all job postings
 *     description: Returns a list of all job postings.
 *     tags: [Jobs]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of jobs retrieved successfully
 *       401:
 *         description: Unauthorized
 */
router.get("/all", async (req, res) => {
  const result = await getAllJobs();
  return res.send(result);
});

/**
 * @swagger
 * /api/jobs/delete/{id}:
 *   delete:
 *     summary: Delete a job posting
 *     description: Deletes a job posting by its ID.
 *     tags: [Job]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: The ID of the job to delete
 *     responses:
 *       200:
 *         description: Job deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Job deleted successfully"
 *       401:
 *         description: Unauthorized — invalid or missing token
 *       404:
 *         description: Job not found
 *       500:
 *         description: Internal server error
 */
/**
 * @swagger
 * /api/jobs/delete/{id}:
 *   delete:
 *     summary: Delete a job posting
 *     description: Deletes a job posting by its ID.
 *     tags: [Jobs]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the job to delete
 *     responses:
 *       200:
 *         description: Job deleted successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Job not found
 */
router.delete("/delete/:id", verifyToken, auditMiddleware("JOB_DELETE"), async (req, res) => {
  const { id } = req.params;
  console.log("my get  job", id)
  const result = await deleteJob(id);
  return res.send(result);
});

/**
 * @swagger
 * /api/jobs/get/{id}:
 *   get:
 *     summary: Get a specific job posting
 *     description: Fetches details of a job posting by its ID.
 *     tags: [Job]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: The ID of the job to retrieve
 *     responses:
 *       200:
 *         description: Job retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   example: 1
 *                 job_title:
 *                   type: string
 *                   example: "Frontend Developer"
 *                 description:
 *                   type: string
 *                   example: "Responsible for developing and maintaining the company’s web applications using React.js."
 *                 created_by:
 *                   type: string
 *                   example: "admin@company.com"
 *                 created_at:
 *                   type: string
 *                   format: date-time
 *                   example: "2025-11-07T18:30:00Z"
 *       401:
 *         description: Unauthorized — invalid or missing token
 *       404:
 *         description: Job not found
 *       500:
 *         description: Internal server error
 */
/**
 * @swagger
 * /api/jobs/get/{id}:
 *   get:
 *     summary: Get a specific job posting
 *     description: Retrieves details of a job by its ID.
 *     tags: [Jobs]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the job
 *     responses:
 *       200:
 *         description: Job details retrieved successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Job not found
 */
router.get("/get/:id", async (req, res) => {
  const { id } = req.params;
  const result = await getJobListingById(id);
  return res.send(result);
});

/**
 * @swagger
 * /api/jobs/update:
 *   patch:
 *     summary: Update a job posting
 *     description: Updates the details of an existing job posting. Requires job title and description.
 *     tags: [Job]
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
 *               - job_title
 *               - description
 *             properties:
 *               id:
 *                 type: integer
 *                 example: 1
 *               job_title:
 *                 type: string
 *                 example: "Frontend Developer"
 *               description:
 *                 type: string
 *                 example: "Responsible for developing and maintaining web applications using React.js."
 *     responses:
 *       200:
 *         description: Job updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Job updated successfully"
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                       example: 1
 *                     job_title:
 *                       type: string
 *                       example: "Frontend Developer"
 *                     description:
 *                       type: string
 *                       example: "Responsible for developing and maintaining web applications using React.js."
 *                     updated_at:
 *                       type: string
 *                       format: date-time
 *                       example: "2025-11-07T20:45:32Z"
 *       400:
 *         description: Validation error or missing fields
 *       401:
 *         description: Unauthorized — invalid or missing token
 *       500:
 *         description: Internal server error
 */
/**
 * @swagger
 * /api/jobs/update:
 *   patch:
 *     summary: Update a job posting
 *     description: Updates details of an existing job posting.
 *     tags: [Jobs]
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
 *             properties:
 *               id:
 *                 type: integer
 *                 example: 1
 *               job_title:
 *                 type: string
 *                 example: "Frontend Developer"
 *               description:
 *                 type: string
 *                 example: "Updated description"
 *               status:
 *                 type: string
 *                 example: "active"
 *     responses:
 *       200:
 *         description: Job updated successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.patch("/update", verifyToken, auditMiddleware("JOB_UPDATE"), validateJobUpdate, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: "Experienced some errors",
      statusCode: 400,
      data: errors.array(),
    });
  }

  const result = await updateJobListing(req);
  return res.send(result);
});




export default router;
