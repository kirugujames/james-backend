import express from 'express';
import dotenv from 'dotenv';
import cors from "cors";
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import sequelize from "./database/database.js";

//models
import { Sequelize } from "sequelize";
import { User, Role } from "./auth/models/index.js";
import Blog from "./blog/Models/Blog.js";
import BlogCategory from "./blog/Models/BlogCategory.js";
import Comment from "./blog/Models/Comments.js";
import Donation from "./donations/Models/Donation.js";
import Merchandise from "./merchandise/Models/Merchandise.js";
import PoliticalApp from "./political-position/Models/PoliticalApp.js";
import AuditTrail from "./audit-trails/Models/AuditTrail.js";
import Volunteer from "./volunteer/Models/Volunteer.js";
import ContactUs from "./contact-us/Models/ContactUs.js";
import MemberRegistration from "./member-registration/models/memberRegistration.js";
import Job from "./jobs/Models/Job.js";
import JobApplication from "./jobs/Models/JobApplication.js";
import Event from "./events/Models/Event.js";
import MpesaPayment from "./mpesa/Models/MpesaPayment.js";
import County from "./locations/Models/County.js";
import Subcounty from "./locations/Models/Subcounty.js";
import Ward from "./locations/Models/Ward.js";

// Routers
import authRouter from './auth/auth-router.js';
import registerRouter from './member-registration/registeration-router.js';
import blogRouter from './blog/blog-router.js';
import jobRouter from "./jobs/job-router.js";
import eventRouter from "./events/events-router.js";
import aspirantRouter from "./aspirants/aspirant-router.js";
import donationRouter from "./donations/donation-router.js";
import merchRouter from "./merchandise/merchandise-router.js";
import politicalRouter from "./political-position/political-app-router.js";
import volunteerRouter from "./volunteer/volunteer-router.js";
import contactRouter from "./contact-us/contact-us-router.js";
import auditRouter from "./audit-trails/audit-trail-router.js";
import mpesaRouter from "./mpesa/mpesa-router.js";
import locationRouter from "./locations/location-router.js";
import partyPositionRouter from "./party-positions/party-position-router.js";

dotenv.config();
const app = express();

app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(cors());

// Load environment variables
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || process.env.VERCEL_URL
  ? `https://${process.env.VERCEL_URL}`
  : 'http://localhost';

// Swagger setup
import path from 'path';

const apiPaths = [
  "auth/*.js",
  "blog/*.js",
  "events/*.js",
  "jobs/*.js",
  "member-registration/*.js",
  "aspirants/*.js",
  "donations/*.js",
  "political-position/*.js",
  "volunteer/*.js",
  "contact-us/*.js",
  "audit-trails/*.js",
  "mpesa/*.js",
  "locations/*.js",
  "merchandise/*.js",
  "party-positions/*.js",
].map(file => path.resolve(process.cwd(), file));

console.log("DEBUG: Current Working Directory:", process.cwd());
console.log("DEBUG: Resolved Swagger Paths:", apiPaths);

export const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "My Express API",
      version: "1.0.0",
      description: "API documentation for Shikana Frontliner Party",
    },
    servers: [
      {
        url: process.env.VERCEL_URL ? `http://${process.env.VERCEL_URL}` : `${BASE_URL}:${PORT}`,
        description: process.env.VERCEL ? "Production Server" : "Development Server"
      }
    ],
    tags: [
      { name: "Auth", description: "Authentication and account management APIs" },
      { name: "Member", description: "Member registration and profile management APIs" },
      { name: "Blog", description: "Blog management APIs" },
      { name: "Role", description: "User role and permission management APIs" },
      { name: "Job", description: "Job listing, applications and creation APIs" },
      { name: "Events", description: "Events listing, booking and creation APIs" },
      { name: "Donations", description: "Donation handling APIs" },
      { name: "Political Applications", description: "Political application APIs" },
      { name: "Volunteer", description: "Volunteer management APIs" },
      { name: "Contact", description: "Contact form and inquiries APIs" },
      { name: "Audit", description: "Audit trail and logging APIs" },
      { name: "M-Pesa", description: "M-Pesa payment and STK push APIs" },
      { name: "Locations", description: "Counties, subcounties, and wards APIs" }
    ],
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
      },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: apiPaths,
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, {
  customCssUrl: 'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.0.0/swagger-ui.min.css',
  customJs: [
    'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.0.0/swagger-ui-bundle.min.js',
    'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.0.0/swagger-ui-standalone-preset.min.js'
  ]
}));

// Model relationships
Blog.hasMany(Comment, { foreignKey: "blog_id", onDelete: "CASCADE" });
Comment.belongsTo(Blog, { foreignKey: "blog_id" });

User.hasMany(PoliticalApp, { foreignKey: "user_id" });
PoliticalApp.belongsTo(User, { foreignKey: "user_id" });

Event.hasMany(Volunteer, { foreignKey: "event_id" });
Volunteer.belongsTo(Event, { foreignKey: "event_id" });

MemberRegistration.hasMany(Donation, { foreignKey: "member_id" });

Job.hasMany(JobApplication, { foreignKey: "job_id", onDelete: "CASCADE" });
JobApplication.belongsTo(Job, { foreignKey: "job_id" });

// Location relationships
County.hasMany(Subcounty, { foreignKey: "county_id", onDelete: "CASCADE" });
Subcounty.belongsTo(County, { foreignKey: "county_id" });

Subcounty.hasMany(Ward, { foreignKey: "subcounty_id", onDelete: "CASCADE" });
Ward.belongsTo(Subcounty, { foreignKey: "subcounty_id" });

// Routes - Define these BEFORE starting the server
app.use('/api/users', authRouter);
app.use('/api/members', registerRouter);
app.use('/api/blog', blogRouter);
app.use("/api/jobs", jobRouter);
app.use("/api/events", eventRouter);
app.use("/api/aspirants", aspirantRouter);
app.use("/api/donations", donationRouter);
app.use("/api/merchandise", merchRouter);
app.use("/api/political-applications", politicalRouter);
app.use("/api/volunteers", volunteerRouter);
app.use("/api/contact", contactRouter);
app.use("/api/audit", auditRouter);
app.use("/api/mpesa", mpesaRouter);
app.use("/api/locations", locationRouter);
app.use("/api/party-positions", partyPositionRouter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Server is running',
    environment: process.env.VERCEL ? 'production' : 'development'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Shikana Frontliner Party API',
    docs: '/api-docs'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send({
    message: 'Internal server error',
    statusCode: 500,
    data: null
  });
});

// Initialize database connection
let dbInitialized = false;

async function initializeDatabase() {
  if (dbInitialized) return;

  try {
    await sequelize.authenticate();
    console.log("Database connected successfully");

    // DON'T use sequelize.sync() in production
    // Tables should already exist in cPanel MySQL
    if (!process.env.VERCEL && process.env.NODE_ENV !== 'production') {
      // Only sync in local development
      await sequelize.sync({ alter: true });
      console.log("Tables created/updated successfully");
    }

    dbInitialized = true;
  } catch (err) {
    console.error("Failed to initialize database:", err.message);
    throw err;
  }
}

// For local development - start server
if (!process.env.VERCEL) {
  (async () => {
    try {
      await initializeDatabase();

      app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Swagger docs available at ${BASE_URL}:${PORT}/api-docs`);
      });
    } catch (err) {
      console.error("Failed to start server:", err.message);
      process.exit(1);
    }
  })();
}

// Export for Vercel serverless
export default async function handler(req, res) {
  // Initialize database on first request
  if (!dbInitialized) {
    await initializeDatabase();
  }

  return app(req, res);
}