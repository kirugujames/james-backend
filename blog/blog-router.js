import express from "express";
import { body, validationResult } from "express-validator";
import dotenv from "dotenv";
import {
  createBlog,
  getAllBlog,
  getBlogById,
  deleteBlogById,
  updateBlogById,
  addBlogCategory,
  getAllBlogCategory,
  getAllBlogByCategory,
  getMainBlog,
  getLandingBlogs
} from "../blog/blog-controller.js";
import {
  commentOnBlog,
  deleteComment,
  getCommentById,
  getCommentByBlogId,
  getAllComments,
} from "../blog/comment-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

dotenv.config();
const router = express.Router();

// Validation rules
const validateBlog = [
  body("title").notEmpty().withMessage("Title is required"),
  body("category").notEmpty().withMessage("Category is required"),
  body("content").notEmpty().withMessage("Content is required"),
  body("image").notEmpty().withMessage("Image is required"),
];

const validateBlogUpdate = [
  body("id").notEmpty().withMessage("Blog ID is required"),
  body("title").optional(),
  body("category").optional(),
  body("content").optional(),
  body("image").optional(),
];

const validateComment = [
  body("blog_id").notEmpty().withMessage("Comment id is required"),
  body("commenter_name").notEmpty().withMessage("commenter name is required"),
  body("email").notEmpty().withMessage(" email is required"),
  body("message").notEmpty().withMessage("message is required"),
];


/**
 * @swagger
 * /api/blog/add:
 *   post:
 *     summary: Create a new blog post
 *     description: Adds a new blog post to the system with title, category, content, and image.
 *     tags: [Blog]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *               - category
 *               - content
 *               - image
 *             properties:
 *               title:
 *                 type: string
 *                 example: "AI and the Future of Journalism"
 *               category:
 *                 type: string
 *                 example: "Technology"
 *               content:
 *                 type: string
 *                 example: "Artificial Intelligence is redefining how news is produced and consumed worldwide."
 *               image:
 *                 type: string
 *                 example: "ai-journalism.jpg"
 *               isMain:
 *                  type: character
 *                  example: 'Y'
 *     responses:
 *       200:
 *         description: Blog post created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Blog created successfully"
 *       400:
 *         description: Validation error
 *       500:
 *         description: Internal server error
 */
router.post("/add", verifyToken, auditMiddleware("BLOG_CREATE"), validateBlog, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array(), statusCode: 400 });
  }
  const response = await createBlog(req);
  return res.send(response);
});


/**
 * @swagger
 * /api/blog/getMainBlog:
 *   get:
 *     summary: Get main blog posts
 *     description: Returns blog articles filtered by the `isMain` flag.
 *     tags: [Blog]
 *     parameters:
 *       - in: query
 *         name: isMain
 *         schema:
 *           type: string
 *           example: "Y"
 *         required: false
 *         description: Flag to filter main blog posts. (Y/N)
 *     responses:
 *       200:
 *         description: Successfully returned blog data
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
 *                   title:
 *                     type: string
 *                     example: "The Role of Youth in Shaping Kenya’s Political Future"
 *                   category:
 *                     type: string
 *                     example: "Politics"
 *                   posted_by:
 *                     type: string
 *                     example: "James Maina"
 *                   posted_date:
 *                     type: string
 *                     format: date-time
 *                     example: "2025-11-06T20:45:32Z"
 *                   content:
 *                     type: string
 *                     example: "Kenya's young population holds the key to the nation's democratic transformation."
 *                   image:
 *                     type: string
 *                     example: "youth-politics-kenya.jpg"
 *       500:
 *         description: Internal server error
 */
router.get("/getMainBlog", async (req, res) => {
  const { isMain } = req.query;
  const response = await getMainBlog(isMain);
  return res.send(response);
});

/**
 * @swagger
 * /api/blog/all:
 *   get:
 *     summary: Get all blog posts
 *     description: Fetches all blog posts from the system, including title, category, author, and content.
 *     tags: [Blog]
 *     responses:
 *       200:
 *         description: Successfully retrieved all blog posts
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
 *                       title:
 *                         type: string
 *                         example: "The Role of Youth in Shaping Kenya’s Political Future"
 *                       category:
 *                         type: string
 *                         example: "Politics"
 *                       posted_by:
 *                         type: string
 *                         example: "James Maina"
 *                       posted_date:
 *                         type: string
 *                         format: date-time
 *                         example: "2025-11-06T20:45:32Z"
 *                       content:
 *                         type: string
 *                         example: "Kenya's young population holds the key to the nation's democratic transformation."
 *                       image:
 *                         type: string
 *                         example: "youth-politics-kenya.jpg"
 *       500:
 *         description: Internal server error
 */
router.get("/all", async (req, res) => {
  const response = await getAllBlog();
  return res.send(response);
});

router.get("/landing", async (req, res) => {
  const result = await getLandingBlogs();
  return res.send(result);
});

/**
 * @swagger
 * /api/blog/get-by-id/{id}:
 *   get:
 *     summary: Get a blog post by ID
 *     description: Fetch a specific blog post using its unique ID.
 *     tags: [Blog]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: The unique identifier of the blog post
 *     responses:
 *       200:
 *         description: Successfully retrieved the blog post
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "success"
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "6737b0fe2af8e937bb418b8c"
 *                     title:
 *                       type: string
 *                       example: "The Future of Artificial Intelligence in Media"
 *                     category:
 *                       type: string
 *                       example: "Technology"
 *                     content:
 *                       type: string
 *                       example: "Artificial Intelligence is transforming the global media landscape..."
 *                     posted_by:
 *                       type: string
 *                       example: "James Maina"
 *                     posted_date:
 *                       type: string
 *                       format: date-time
 *                       example: "2025-11-06T20:45:32Z"
 *                     image:
 *                       type: string
 *                       example: "ai-future-media.jpg"
 *       400:
 *         description: Invalid blog ID or validation error
 *       404:
 *         description: Blog post not found
 *       500:
 *         description: Internal server error
 */
router.get("/get-by-id/:id", async (req, res) => {
  const id = req.params.id;
  const response = await getBlogById(id);
  return res.send(response);
});

/**
 * @swagger
 * /api/blog/delete/{id}:
 *   delete:
 *     summary: Delete a blog by ID
 *     description: Deletes a specific blog post based on its unique ID. Requires authentication via a valid token.
 *     tags: [Blog]
 *     security:
 *       - bearerAuth: []   # Token-based auth
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The unique ID of the blog to delete
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Blog deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Blog deleted successfully
 *       401:
 *         description: Unauthorized — missing or invalid token
 *       404:
 *         description: Blog not found
 *       500:
 *         description: Internal server error
 */
router.delete("/delete/:id", verifyToken, auditMiddleware("BLOG_DELETE"), async (req, res) => {
  const id = req.params.id;
  const result = await deleteBlogById(id);
  return res.send(result);
});

/**
 * @swagger
 * /api/blog/update:
 *   patch:
 *     summary: Update an existing blog
 *     description: Updates a specific blog post. The blog ID must be provided in the request body.
 *     tags: [Blog]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id:
 *                 type: string
 *                 example: "672cbd1c9f4c3e14b894b312"
 *               title:
 *                 type: string
 *                 example: "Updated Blog Title"
 *               content:
 *                 type: string
 *                 example: "This is the updated content of the blog post."
 *               image:
 *                 type: string
 *                 example: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
 *     responses:
 *       200:
 *         description: Blog updated successfully
 *       400:
 *         description: Validation error — invalid or missing fields
 *       404:
 *         description: Blog not found
 *       500:
 *         description: Internal server error
 */
router.patch("/update", verifyToken, auditMiddleware("BLOG_UPDATE"), validateBlogUpdate, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array(), statusCode: 400 });
  }
  const response = await updateBlogById(req);
  return res.send(response);
});

/**
 * @swagger
 * /api/blog/comment:
 *   post:
 *     summary: Add a comment to a blog
 *     tags: [Blog]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - blog_id
 *               - message
 *               - email
 *               - commenter_name
 *             properties:
 *               blog_id:
 *                 type: integer
 *                 example: 5
 *               message:
 *                 type: string
 *                 example: Great post! I really enjoyed reading this.
 *               email:
 *                 type: string
 *                 example: i@gmail.com
 *               commenter_name:
 *                 type: string
 *                 example: John S
 *     responses:
 *       200:
 *         description: Comment added successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Comment added successfully
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       400:
 *         description: Validation error — Invalid or missing fields
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
 *                         example: Comment field is required
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

router.post("/comment", auditMiddleware("BLOG_COMMENT"), validateComment, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array(), statusCode: 400 });
  }
  const response = await commentOnBlog(req);
  return res.send(response);
});

/**
 * @swagger
 * /api/blog/add/create/blogCategory:
 *   post:
 *     summary: Create a new blog category
 *     tags: [Blog]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - category
 *             properties:
 *               category:
 *                 type: string
 *                 example: Technology
 *     responses:
 *       200:
 *         description: Blog category created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Blog category added successfully
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       400:
 *         description: Validation error — Invalid or missing fields
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
 *                         example: Category field is required
 *                 statusCode:
 *                   type: integer
 *                   example: 400
 *       500:
 *         description: Internal server error
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
router.post("/add/create/blogCategory", verifyToken, auditMiddleware("BLOG_CATEGORY_CREATE"), async (req, res) => {
  const response = await addBlogCategory(req);
  return res.send(response);
});
/**
 * @swagger
 * /api/blog/get/all/blogCategory:
 *   get:
 *     summary: Retrieve all blog categories
 *     tags: [Blog]
 *     responses:
 *       200:
 *         description: Successfully retrieved all blog categories
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Blog categories fetched successfully
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 1
 *                       category:
 *                         type: string
 *                         example: Technology
 *                       createdAt:
 *                         type: string
 *                         example: 2025-01-01T12:00:00Z
 *                       updatedAt:
 *                         type: string
 *                         example: 2025-01-01T12:00:00Z
 *       500:
 *         description: Internal server error
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
router.get("/get/all/blogCategory", async (req, res) => {
  const response = await getAllBlogCategory();
  return res.send(response);
});


/**
 * @swagger
 * /api/blog/get/all/blog/by/category:
 *   get:
 *     summary: Retrieve all blogs by category
 *     tags: [Blog]
 *     parameters:
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         required: true
 *         description: The category to filter blogs by
 *         example: Technology
 *     responses:
 *       200:
 *         description: Successfully retrieved blogs for the given category
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Blogs fetched successfully for the category
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 1
 *                       title:
 *                         type: string
 *                         example: Latest Tech Trends
 *                       content:
 *                         type: string
 *                         example: This is a detailed blog post about technology...
 *                       category:
 *                         type: string
 *                         example: Technology
 *                       createdAt:
 *                         type: string
 *                         example: 2025-01-01T12:00:00Z
 *                       updatedAt:
 *                         type: string
 *                         example: 2025-01-01T12:00:00Z
 *       400:
 *         description: Missing or invalid category parameter
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Category query parameter is required
 *                 statusCode:
 *                   type: integer
 *                   example: 400
 *       500:
 *         description: Internal server error
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
router.get("/get/all/blog/by/category", async (req, res) => {
  const response = await getAllBlogByCategory(req);
  return res.send(response);
});

/**
 * @swagger
 * /api/blog/delete-comments/{id}:
 *   delete:
 *     summary: Delete all comments for a specific blog
 *     description: Removes all comments linked to a specific blog by its ID.
 *     tags: [Blog]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The unique ID of the blog whose comments should be deleted
 *         schema:
 *           type: integer
 *         example: 5
 *     responses:
 *       200:
 *         description: Comments deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Comments deleted successfully
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       404:
 *         description: Blog or comments not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: No comments found for the given blog ID
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
router.delete("/delete-comments/:id", async (req, res) => {
  const id = req.params.id;
  console.log("Deleting comments for blog ID:", id);
  const result = await deleteComment(id);
  return res.send(result);
});


/**
 * @swagger
 * /api/blog/comments/{id}:
 *   get:
 *     summary: Get all comments for a specific blog
 *     description: Retrieves all comments associated with a given blog post by its ID.
 *     tags: [Blog]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The unique ID of the blog
 *         schema:
 *           type: integer
 *         example: 5
 *     responses:
 *       200:
 *         description: Comments retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Comments retrieved successfully
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 1
 *                       blog_id:
 *                         type: integer
 *                         example: 5
 *                       commenter_name:
 *                         type: string
 *                         example: John Doe
 *                       comment:
 *                         type: string
 *                         example: Great article! I learned a lot.
 *                       date_created:
 *                         type: string
 *                         format: date-time
 *                         example: 2025-11-06T12:34:56Z
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       404:
 *         description: No comments found for this blog
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: No comments found for the given blog ID
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
router.get("/comments/:id", async (req, res) => {
  const id = req.params.id;
  console.log("Fetching comments for blog ID:", id);
  const result = await getCommentById(id);
  return res.send(result);
});

/**
 * @swagger
 * /api/blog/comments-by-blog/{blog_id}:
 *   get:
 *     summary: Get comments by blog ID
 *     description: Retrieve all comments associated with a specific blog post by its unique blog ID.
 *     tags: [Blog]
 *     parameters:
 *       - in: path
 *         name: blog_id
 *         required: true
 *         description: The unique ID of the blog whose comments are to be retrieved
 *         schema:
 *           type: integer
 *         example: 7
 *     responses:
 *       200:
 *         description: Comments retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Comments retrieved successfully
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 1
 *                       blog_id:
 *                         type: integer
 *                         example: 7
 *                       commenter_name:
 *                         type: string
 *                         example: Jane Doe
 *                       comment:
 *                         type: string
 *                         example: Very informative post!
 *                       date_created:
 *                         type: string
 *                         format: date-time
 *                         example: 2025-11-06T14:22:35Z
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       404:
 *         description: No comments found for this blog
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: No comments found for the given blog ID
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
router.get("/comments-by-blog/:blog_id", async (req, res) => {
  const id = req.params.blog_id;
  console.log("Fetching comments for blog ID:", id);
  const result = await getCommentByBlogId(id);
  return res.send(result);
});

/**
 * @swagger
 * /api/blog/all/comments:
 *   get:
 *     summary: Get all comments
 *     description: Retrieve all comments available in the system across all blog posts.
 *     tags: [Blog]
 *     responses:
 *       200:
 *         description: Comments retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: All comments retrieved successfully
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 1
 *                       blog_id:
 *                         type: integer
 *                         example: 5
 *                       commenter_name:
 *                         type: string
 *                         example: Alice Mwangi
 *                       comment:
 *                         type: string
 *                         example: This is a very insightful article.
 *                       date_created:
 *                         type: string
 *                         format: date-time
 *                         example: 2025-11-06T14:45:00Z
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       404:
 *         description: No comments found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: No comments found
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
router.get("/all/comments", async (req, res) => {
  const result = await getAllComments();
  return res.send(result);
});











export default router;
