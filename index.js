import express from 'express';
import dotenv from 'dotenv';
import { startSessionCleaner } from './utils/cron_job.js';
import authRouter from './auth/auth-router.js';
import eventRouter from "./events/events-router.js";
import blogRouter from './blog/blog-router.js';
import jobRouter from "./jobs/job-router.js";
import sequelize from "./database/database.js";
import registerRouter from './member-registration/registeration-router.js';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import cors from "cors";

dotenv.config();

const app = express();

app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(cors());

startSessionCleaner();

// Load environment variables
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || 'http://localhost';

// Swagger setup
export const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "My Express API",
      version: "1.0.0",
      description: "API documentation for shikana frontliner party",
    },
    servers: [
      {
        url: `${BASE_URL}:${PORT}`,
        description: "Development Server",
      },
    ],
    tags: [
      {
        name: "Auth",
        description: "Authentication and account management APIs",
      },
      {
        name: "Member",
        description: "Member registration and profile management APIs",
      },
      {
        name: "Blog",
        description: "Blog management APIs",
      },
      {
        name: "Role",
        description: "User role and permission management APIs",
      },
      {
        name: "Job",
        description: "Job listing ,  applications and  creation apis",
      },
      {
        name: "Events",
        description: "Events listing ,  booking and  creation apis",
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: [
    "./auth/*.js",
    "./blog/*.js",
    "./events/*.js",
    "./jobs/*.js",
    "./member-registration/*.js",
  ],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Routes
//authentication
app.use('/api/users', authRouter);

// member creations
app.use('/api/members', registerRouter);

//blog listing
app.use('/api/blog', blogRouter)

//job listing ,  appliction and  creation
app.use("/api/jobs", jobRouter);

//events creation apis
app.use("/api/events", eventRouter)


// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send({ message: 'Internal server error', statusCode: 500, data: null });
});

// Start server
// Start server only after DB is ready
(async () => {
  try {
    // Connect to DB
    await sequelize.authenticate();
    console.log("Database connected successfully");

    // Sync models (create tables)
    await sequelize.sync({ alter: false});
    console.log("Tables created/updated successfully");

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`📘 Swagger docs available at ${BASE_URL}:${PORT}/api-docs`);
    });
  } catch (err) {
    console.error("Failed to initialize database:", err.message);
  }
})();

