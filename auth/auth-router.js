import express from "express";
import {
  registerUser,
  authenticateUser,
  verifyAuthOtp,
  resendOtp,
  forgotPassword,
  resetPasswordWithToken,
  toggleUserStatus,
  logoutUser,
  createRole,
  getRoles,
  updateRole,
  deleteRole,
  getAllUsers,
  refreshAccessToken,
  changePassword,
  updateUser
} from "./auth-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

const router = express.Router();
/**
 * @swagger
 * /api/users/register:
 *   post:
 *     summary: Register a new user
 *     description: Creates a new user account with email, username, role, and password.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - first_name
 *               - last_name
 *               - role_id
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               role_id:
 *                 type: integer
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User successfully registered
 *       400:
 *         description: Validation error
 */

router.post("/register", auditMiddleware("USER_REGISTER"), async (req, res) => {
  const result = await registerUser(req);
  return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/users/login:
 *   post:
 *     summary: Authenticate user
 *     description: Login using username and password to receive a JWT token.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 */
router.post("/login", auditMiddleware("USER_LOGIN"), async (req, res) => {
  const result = await authenticateUser(req);
  return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/users/verify-otp:
 *   post:
 *     summary: Verify OTP code
 *     description: Verify the one-time password (OTP) sent to the user's email.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - otp
 *             properties:
 *               email:
 *                 type: string
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP verified successfully
 *       400:
 *         description: Invalid or expired OTP
 */

router.post("/verify-otp", auditMiddleware("VERIFY_OTP"), async (req, res) => {
  const result = await verifyAuthOtp(req);
  return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/users/resend-otp:
 *   post:
 *     summary: Resend OTP
 *     description: Send a new OTP to the user’s email.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *       400:
 *         description: Invalid email
 */

router.post("/resend-otp", async (req, res) => {
  const result = await resendOtp(req);
  return res.status(result.statusCode).json(result);
});

// Forgot Password
/**
 * @swagger
 * /api/users/forgot-password:
 *   post:
 *     summary: Request password reset link
 *     description: Sends a password reset link to the user's email if it exists.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: Reset link sent
 *       404:
 *         description: User not found
 */
router.post("/forgot-password", auditMiddleware("FORGOT_PASSWORD"), async (req, res) => {
  const result = await forgotPassword(req);
  return res.status(result.statusCode).json(result);
});

// Reset Password with Token
/**
 * @swagger
 * /api/users/reset-password-token:
 *   post:
 *     summary: Reset password using token
 *     description: Resets the user's password using a valid reset token from email.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - newPassword
 *             properties:
 *               token:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password reset successful
 *       400:
 *         description: Invalid or expired token
 */
router.post("/reset-password-token", auditMiddleware("RESET_PASSWORD"), async (req, res) => {
  const result = await resetPasswordWithToken(req);
  return res.status(result.statusCode).json(result);
});

// Change Password (Authenticated)
/**
 * @swagger
 * /api/users/change-password:
 *   patch:
 *     summary: Change password
 *     description: Allows a user to change their password by providing their email, old password, and new password.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - oldPassword
 *               - newPassword
 *             properties:
 *               email:
 *                 type: string
 *               oldPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       400:
 *         description: Invalid current password
 *       404:
 *         description: User not found
 */
router.patch("/change-password", auditMiddleware("CHANGE_PASSWORD"), async (req, res) => {
  const result = await changePassword(req);
  return res.status(result.statusCode).json(result);
});

// Toggle User Status (Admin)
router.post("/toggle-status", verifyToken, auditMiddleware("TOGGLE_USER_STATUS"), async (req, res) => {
  const result = await toggleUserStatus(req);
  return res.status(result.statusCode).json(result);
});

// Refresh Token
router.post("/refresh-token", async (req, res) => {
  const result = await refreshAccessToken(req);
  return res.status(result.statusCode).json(result);
});



/**
 * @swagger
 * /api/users/logout:
 *   post:
 *     summary: Logout user
 *     description: Logs out the user by invalidating their session token.
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *       401:
 *         description: Unauthorized (invalid or missing token)
 *       

 */
router.post("/logout", verifyToken, async (req, res) => {
  const result = await logoutUser(req);
  return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/users/role:
 *   post:
 *     summary: Create a new user role
 *     tags: [Role]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *             properties:
 *               name:
 *                 type: string
 *                 example: Admin
 *               description:
 *                 type: string
 *                 example: Has full access to the system.
 *     responses:
 *       200:
 *         description: Role created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Role created successfully
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       400:
 *         description: Bad request — Invalid data provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Validation error — name is required
 *                 statusCode:
 *                   type: integer
 *                   example: 400
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Internal server error
 *                 statusCode:
 *                   type: integer
 *                   example: 500
 */
router.post("/role", async (req, res) => {
  const result = await createRole(req);
  return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/users/roles:
 *   get:
 *     summary: Get all roles
 *     tags: [Role]
 *     responses:
 *       200:
 *         description: Roles retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Roles retrieved successfully
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 1
 *                       name:
 *                         type: string
 *                         example: Admin
 *                       description:
 *                         type: string
 *                         example: Has full access to the system.
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Internal server error
 *                 statusCode:
 *                   type: integer
 *                   example: 500
 */
router.get("/roles", async (req, res) => {
  const result = await getRoles(req);
  return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/users/role/get/{id}:
 *   get:
 *     summary: Get a role by ID
 *     tags: [Role]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the role to retrieve
 *         schema:
 *           type: integer
 *           example: 1
 *     responses:
 *       200:
 *         description: Role retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Role retrieved successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                       example: 1
 *                     name:
 *                       type: string
 *                       example: Admin
 *                     description:
 *                       type: string
 *                       example: Has full access to the system.
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       404:
 *         description: Role not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Role not found
 *                 statusCode:
 *                   type: integer
 *                   example: 404
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Internal server error
 *                 statusCode:
 *                   type: integer
 *                   example: 500
 */
router.get("/role/get/:id", async (req, res) => {
  const { id } = req.params;
  const result = await getRoleById(id);
  return res.send(result);
});


/**
 * @swagger
 * /api/users/role/update:
 *   patch:
 *     summary: Update a role by ID
 *     tags: [Role]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - id
 *               - name
 *             properties:
 *               id:
 *                 type: integer
 *                 example: 1
 *               name:
 *                 type: string
 *                 example: Editor
 *               description:
 *                 type: string
 *                 example: Can edit and manage content.
 *     responses:
 *       200:
 *         description: Role updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Role updated successfully
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 errors:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       msg:
 *                         type: string
 *                         example: Name field is required
 *       404:
 *         description: Role not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: No role found with the given ID
 *                 statusCode:
 *                   type: integer
 *                   example: 404
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Internal server error
 *                 statusCode:
 *                   type: integer
 *                   example: 500
 */
router.patch("/role/update", async (req, res) => {
  const result = await updateRole(req);
  return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/users/role/{id}:
 *   delete:
 *     summary: Delete a role by ID
 *     tags: [Role]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         example: 1
 *     responses:
 *       200:
 *         description: Role deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Role deleted successfully
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       404:
 *         description: Role not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: No role found with the given ID
 *                 statusCode:
 *                   type: integer
 *                   example: 404
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Internal server error
 *                 statusCode:
 *                   type: integer
 *                   example: 500
 */
router.delete("/role/:id", async (req, res) => {
  const result = await deleteRole(req);
  return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 *  /api/users/get-all-users:
 *   get:
 *     summary: Get all users
 *     description: Fetches and returns a list of all users from the system.
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users retrieved successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                     example: 1
 *                   name:
 *                     type: string
 *                     example: John Doe
 *                   email:
 *                     type: string
 *                     example: johndoe@example.com
 *                   first_name:
 *                     type: string
 *                     example: John
 *                   last_name:
 *                     type: string
 *                     example: Doe
 *                   Role:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                       role_name:
 *                         type: string
 *       500:
 *         description: Server error.
 */
router.get("/get-all-users", verifyToken, async (req, res) => {
  const result = await getAllUsers();
  return res.send(result);
});

/**
 * @swagger
 * /api/users/update/{id}:
 *   patch:
 *     summary: Update a user by ID
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               email:
 *                 type: string
 *               role_id:
 *                 type: integer
 *     responses:
 *       200:
 *         description: User updated successfully
 *       404:
 *         description: User not found
 *       409:
 *         description: Email already exists
 *       500:
 *         description: Server error
 */
router.patch("/update/:id", verifyToken, async (req, res) => {
  const result = await updateUser(req);
  return res.status(result.statusCode).json(result);
});

export default router;
