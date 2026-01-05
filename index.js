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
import donationRouter from "./donations/donation-router.js";
import merchRouter from "./merchandise/merchandise-router.js";
import politicalRouter from "./political-position/political-app-router.js";
import volunteerRouter from "./volunteer/volunteer-router.js";
import contactRouter from "./contact-us/contact-us-router.js";
import auditRouter from "./audit-trails/audit-trail-router.js";
import mpesaRouter from "./mpesa/mpesa-router.js";
import locationRouter from "./locations/location-router.js";


dotenv.config();
const app = express();

app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(cors());

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
      description: "API documentation for Shikana Frontliner Party",
    },
    servers: [{ url: `${BASE_URL}:${PORT}`, description: "Development Server" }],
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
  apis: [
    "./auth/*.js",
    "./blog/*.js",
    "./events/*.js",
    "./jobs/*.js",
    "./member-registration/*.js",
    "./donations/*.js",
    "./political-position/*.js",
    "./volunteer/*.js",
    "./contact-us/*.js",
    "./audit-trails/*.js",
    "./mpesa/*.js",
    "./locations/*.js",
    "./merchandise/*.js",
  ],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));


Blog.hasMany(Comment, { foreignKey: "blog_id", onDelete: "CASCADE" });
Comment.belongsTo(Blog, { foreignKey: "blog_id" });

User.hasMany(PoliticalApp, { foreignKey: "user_id" });
PoliticalApp.belongsTo(User, { foreignKey: "user_id" });

Event.hasMany(Volunteer, { foreignKey: "event_id" });
Volunteer.belongsTo(Event, { foreignKey: "event_id" });

MemberRegistration.hasMany(Donation, { foreignKey: "member_id" });

// Location relationships
County.hasMany(Subcounty, { foreignKey: "county_id", onDelete: "CASCADE" });
Subcounty.belongsTo(County, { foreignKey: "county_id" });

Subcounty.hasMany(Ward, { foreignKey: "subcounty_id", onDelete: "CASCADE" });
Ward.belongsTo(Subcounty, { foreignKey: "subcounty_id" });

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send({ message: 'Internal server error', statusCode: 500, data: null });
});

// Start server after DB connection
(async () => {
  try {
    await sequelize.authenticate();
    console.log("Database connected successfully");

    // Sync models and create/update tables
    // await sequelize.sync({ alter: true });
    console.log("Tables created/updated successfully");

    // Routes
    app.use('/api/users', authRouter);
    app.use('/api/members', registerRouter);
    app.use('/api/blog', blogRouter);
    app.use("/api/jobs", jobRouter);
    app.use("/api/events", eventRouter);
    app.use("/api/donations", donationRouter);
    app.use("/api/merchandise", merchRouter);
    app.use("/api/political-applications", politicalRouter);
    app.use("/api/volunteers", volunteerRouter);
    app.use("/api/contact", contactRouter);
    app.use("/api/audit", auditRouter);
    app.use("/api/mpesa", mpesaRouter);
    app.use("/api/locations", locationRouter);

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Swagger docs available at ${BASE_URL}:${PORT}/api-docs`);
    });
  } catch (err) {
    console.error("Failed to initialize database:", err.message);
  }
})();
