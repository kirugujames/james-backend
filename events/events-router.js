/**
 * @swagger
 * tags:
 *   name: Events
 *   description: APIs for managing events in the system
 */

import express from "express";
import { body, validationResult } from "express-validator";
import dotenv from "dotenv";
import {
  bookAnEvent, getAllBookedEvents,
  createEvent, deleteEventById,
  getAllEvents, getEventById,
  updateAnEvent, updateEvent,
  getEventBookingByEventId,
  getEventBookingByMemberCode,
  getEventBookingById,
  getLandingEvents
} from "./events-controller.js";
import { verifyToken } from "../utils/jwtInterceptor.js";
import { auditMiddleware } from "../utils/audit-service.js";

dotenv.config();

const router = express.Router();

// Validation rules
const validateEventCreation = [
  body("event_type").notEmpty().withMessage("Event type is required"),
  body("title").notEmpty().withMessage("Title is required"),
  body("event_date").notEmpty().withMessage("Event date is required"),
  body("from_time").notEmpty().withMessage("From time is required"),
  body("to_time").notEmpty().withMessage("To time is required"),
  body("location").notEmpty().withMessage("Location is required"),
  body("description").notEmpty().withMessage("Description is required"),
  body("sub_title").notEmpty().withMessage("Subtitle is required"),
  body("image").notEmpty().withMessage("Image is required"),
];

/**
 * @swagger
 * /api/events/add:
 *   post:
 *     summary: Create a new event
 *     description: Adds a new event record to the system. All fields are required.
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - event_type
 *               - title
 *               - event_date
 *               - from_time
 *               - to_time
 *               - location
 *               - description
 *               - sub_title
 *               - image
 *             properties:
 *               event_type:
 *                 type: string
 *                 example: "Conference"
 *               title:
 *                 type: string
 *                 example: "AI Innovations Summit 2025"
 *               event_date:
 *                 type: string
 *                 format: date
 *                 example: "2025-12-05"
 *               from_time:
 *                 type: string
 *                 example: "09:00"
 *               to_time:
 *                 type: string
 *                 example: "16:00"
 *               location:
 *                 type: string
 *                 example: "Nairobi International Convention Centre"
 *               description:
 *                 type: string
 *                 example: "A full-day event exploring the latest AI innovations and their societal impacts."
 *               sub_title:
 *                 type: string
 *                 example: "Exploring Tomorrow's AI Today"
 *               image:
 *                 type: string
 *                 example: "base64encodedimage=="
 *     responses:
 *       200:
 *         description: Event created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Event created successfully"
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *                 data:
 *                   type: object
 *                   example:
 *                     id: 1
 *                     title: "AI Innovations Summit 2025"
 *                     event_date: "2025-12-05"
 *       400:
 *         description: Validation error — Missing or invalid fields
 *       401:
 *         description: Unauthorized — Invalid or missing token
 *       500:
 *         description: Internal server error
 */
router.post("/add", validateEventCreation, verifyToken, auditMiddleware("EVENT_CREATE"), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res
      .status(400)
      .json({ message: "Validation errors", statusCode: 400, data: errors.array() });
  }
  const result = await createEvent(req);
  return res.send(result);
});

/**
 * @swagger
 *  /api/events/all:
 *   get:
 *     summary: Retrieve all events
 *     tags: [Events]
 *     description: Returns a list of all events stored in the system.
 *     responses:
 *       200:
 *         description: A list of events.
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
 *                   event_type:
 *                     type: string
 *                     example: Conference
 *                   title:
 *                     type: string
 *                     example: AI Innovations Summit 2025
 *                   event_date:
 *                     type: string
 *                     format: date
 *                     example: 2025-12-05
 *                   from_time:
 *                     type: string
 *                     example: "09:00"
 *                   to_time:
 *                     type: string
 *                     example: "16:00"
 *                   location:
 *                     type: string
 *                     example: Nairobi International Convention Centre
 *                   description:
 *                     type: string
 *                     example: A full-day event exploring the latest AI innovations and their societal impacts.
 *                   sub_title:
 *                     type: string
 *                     example: Exploring Tomorrow's AI Today
 *                   image:
 *                     type: string
 *                     example: base64encodedimage==
 */
router.get("/all", async (req, res) => {
  const result = await getAllEvents();
  return res.send(result);
});

router.get("/landing", async (req, res) => {
  const result = await getLandingEvents();
  return res.send(result);
});

/**
 * @swagger
 * /api/events/get/by/id/{id}:
 *   get:
 *     summary: Get event by ID
 *     tags: [Events]
 *     description: Retrieve detailed information about a specific event using its unique ID.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: The ID of the event to retrieve
 *         example: 1
 *     responses:
 *       200:
 *         description: Event retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   example: 1
 *                 event_type:
 *                   type: string
 *                   example: Conference
 *                 title:
 *                   type: string
 *                   example: AI Innovations Summit 2025
 *                 event_date:
 *                   type: string
 *                   format: date
 *                   example: 2025-12-05
 *                 from_time:
 *                   type: string
 *                   example: "09:00"
 *                 to_time:
 *                   type: string
 *                   example: "16:00"
 *                 location:
 *                   type: string
 *                   example: Nairobi International Convention Centre
 *                 description:
 *                   type: string
 *                   example: A full-day event exploring the latest AI innovations and their societal impacts.
 *                 sub_title:
 *                   type: string
 *                   example: Exploring Tomorrow's AI Today
 *                 image:
 *                   type: string
 *                   example: base64encodedimage==
 *       404:
 *         description: Event not found
 *       500:
 *         description: Server error
 */
router.get("/get/by/id/:id", async (req, res) => {
  const { id } = req.params;
  const result = await getEventById(id);
  return res.send(result);
});

/**
 * @swagger
 * /api/events/delete/{id}:
 *   delete:
 *     summary: Delete an event by ID
 *     tags: [Events]
 *     description: Permanently removes a specific event from the database using its unique ID.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: The ID of the event to delete
 *         example: 1
 *     responses:
 *       200:
 *         description: Event deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Event deleted successfully
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       404:
 *         description: Event not found
 *       500:
 *         description: Server error
 */
router.delete("/delete/:id", verifyToken, auditMiddleware("EVENT_DELETE"), async (req, res) => {
  const { id } = req.params;
  const result = await deleteEventById(id);
  return res.send(result);
});

/**
 * @swagger
 * /api/events/update:
 *   patch:
 *     summary: Update an existing event
 *     tags: [Events]
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
 *               event_type:
 *                 type: string
 *                 example: Conference
 *               title:
 *                 type: string
 *                 example: AI Innovations Summit 2025
 *               event_date:
 *                 type: string
 *                 format: date
 *                 example: 2025-12-05
 *               from_time:
 *                 type: string
 *                 example: 09:00
 *               to_time:
 *                 type: string
 *                 example: 16:00
 *               location:
 *                 type: string
 *                 example: Nairobi International Convention Centre
 *               description:
 *                 type: string
 *                 example: A full-day event exploring the latest AI innovations and their societal impacts.
 *               sub_title:
 *                 type: string
 *                 example: Exploring Tomorrow's AI Today
 *               image:
 *                 type: string
 *                 description: Base64 encoded image string
 *                 example: base64encodedimage==
 *     responses:
 *       200:
 *         description: Event updated successfully
 *       400:
 *         description: Invalid request or missing required fields
 *       500:
 *         description: Server error while updating the event
 */
router.patch("/update", verifyToken, auditMiddleware("EVENT_UPDATE"), async (req, res) => {
  const result = await updateEvent(req);
  return res.status(result.statusCode).json(result);
});

/**
 * @swagger
 * /api/events/book-event:
 *   post:
 *     summary: Book an event
 *     tags: [Events]
 *     description: Allows a user to book an event by providing event and member details.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - event_id
 *               - member_code
 *             properties:
 *               event_id:
 *                 type: integer
 *                 description: The unique ID of the event to be booked.
 *                 example: 3
 *               member_code:
 *                 type: string
 *                 description: The ID of the member booking the event.
 *                 example: MBR12345
 *     responses:
 *       200:
 *         description: Event booked successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Event booked successfully.
 *       400:
 *         description: Invalid input or missing required fields.
 *       500:
 *         description: Server error while booking the event.
 */
router.post("/book-event", auditMiddleware("EVENT_BOOKING"), async (req, res) => {
  const result = await bookAnEvent(req);
  return res.send(result);
});

/**
 * @swagger
 * /api/events/booking-event/update:
 *   patch:
 *     summary: Update a booked event
 *     tags: [Events]
 *     description: Updates an existing event booking record based on its ID.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - id
 *               - event_id
 *               - member_code
 *             properties:
 *               id:
 *                 type: integer
 *                 description: The unique ID of the booking record to update.
 *                 example: 12
 *               event_id:
 *                 type: integer
 *                 description: The ID of the event associated with this booking.
 *                 example: 5
 *               member_code:
 *                 type: string
 *                 description: The code identifying the member who booked the event.
 *                 example: MBR12345
 *     responses:
 *       200:
 *         description: Booking updated successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Booking updated successfully.
 *                 statusCode:
 *                   type: integer
 *                   example: 200
 *       400:
 *         description: Invalid input or missing required fields.
 *       404:
 *         description: Booking not found.
 *       500:
 *         description: Server error while updating the booking.
 */
router.patch("/booking-event/update", auditMiddleware("EVENT_BOOKING_UPDATE"), async (req, res) => {
  const result = await updateAnEvent(req);
  return res.send(result);
});

/**
 * @swagger
 * /api/events/book-event/all:
 *   get:
 *     summary: Retrieve all booked events
 *     tags: [Events]
 *     description: Fetch a list of all events that have been booked, including details such as the event ID, member code, and booking status.
 *     responses:
 *       200:
 *         description: Successfully retrieved the list of all booked events.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                     description: The unique booking ID.
 *                     example: 1
 *                   event_id:
 *                     type: integer
 *                     description: The ID of the event that was booked.
 *                     example: 5
 *                   member_code:
 *                     type: string
 *                     description: The code of the member who booked the event.
 *                     example: MBR12345
 *                   booking_status:
 *                     type: string
 *                     description: The current status of the booking.
 *                     example: Confirmed
 *                   booking_date:
 *                     type: string
 *                     format: date-time
 *                     description: The date and time when the event was booked.
 *                     example: 2025-11-07T14:30:00Z
 *       404:
 *         description: No booked events found.
 *       500:
 *         description: Server error while retrieving booked events.
 */
router.get("/book-event/all", async (req, res) => {
  const result = await getAllBookedEvents();
  return res.send(result);
});

/**
 * @swagger
 * /api/events/booked-event/get-by-event-id/{event_id}:
 *   get:
 *     summary: Get all bookings for a specific event
 *     tags: [Events]
 *     description: Retrieve all bookings made for a specific event using its unique event ID.
 *     parameters:
 *       - in: path
 *         name: event_id
 *         required: true
 *         schema:
 *           type: integer
 *         description: The unique ID of the event.
 *         example: 3
 *     responses:
 *       200:
 *         description: Successfully retrieved all bookings for the specified event.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   booking_id:
 *                     type: integer
 *                     description: The unique ID of the booking.
 *                     example: 12
 *                   event_id:
 *                     type: integer
 *                     description: The ID of the booked event.
 *                     example: 3
 *                   member_code:
 *                     type: string
 *                     description: The member code of the person who booked the event.
 *                     example: MBR2025
 *                   booking_status:
 *                     type: string
 *                     description: The status of the booking.
 *                     example: Confirmed
 *                   booking_date:
 *                     type: string
 *                     format: date-time
 *                     description: The date and time when the event was booked.
 *                     example: 2025-11-07T10:45:00Z
 *       400:
 *         description: Event ID is missing in the request parameters.
 *       404:
 *         description: No bookings found for the specified event.
 *       500:
 *         description: Server error while retrieving event bookings.
 */
router.get("/booked-event/get-by-event-id/:event_id", async (req, res) => {
  const { event_id } = req.params;
  if (!event_id) {
    return res.send({ message: "event id is required", statusCode: 400 });
  }
  const result = await getEventBookingByEventId(event_id);
  return res.send(result);
});

/**
 * @swagger
 * /api/events/booked-event/get-by-member-code/{member_code}:
 *   get:
 *     summary: Get all events booked by a specific member
 *     tags: [Events]
 *     description: Retrieve all booked events associated with a particular member using their unique member code.
 *     parameters:
 *       - in: path
 *         name: member_code
 *         required: true
 *         schema:
 *           type: string
 *         description: The unique code assigned to a registered member.
 *         example: MBR2025
 *     responses:
 *       200:
 *         description: Successfully retrieved all bookings made by the specified member.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   booking_id:
 *                     type: integer
 *                     description: Unique identifier of the booking.
 *                     example: 15
 *                   event_id:
 *                     type: integer
 *                     description: ID of the booked event.
 *                     example: 7
 *                   member_code:
 *                     type: string
 *                     description: The code of the member who booked the event.
 *                     example: MBR2025
 *                   event_title:
 *                     type: string
 *                     description: Title of the event.
 *                     example: AI Innovations Summit 2025
 *                   booking_status:
 *                     type: string
 *                     description: Current booking status.
 *                     example: Confirmed
 *                   booking_date:
 *                     type: string
 *                     format: date-time
 *                     description: The date and time the booking was made.
 *                     example: 2025-11-07T09:30:00Z
 *       400:
 *         description: Member code is missing in the request parameters.
 *       404:
 *         description: No bookings found for the given member code.
 *       500:
 *         description: Server error while retrieving member's event bookings.
 */
router.get("/booked-event/get-by-member-code/:member_code", async (req, res) => {
  const { member_code } = req.params;
  if (!member_code) {
    return res.send({ message: "member code is required", statusCode: 400 });
  }
  const result = await getEventBookingByMemberCode(member_code);
  return res.send(result);
});

/**
 * @swagger
 * /api/events/booked-event/get-by-id/{id}:
 *   get:
 *     summary: Get booking details by event booking ID
 *     tags: [Events]
 *     description: Retrieve detailed information for a specific event booking using its unique booking ID.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Unique ID of the event booking record.
 *         example: 12
 *     responses:
 *       200:
 *         description: Successfully retrieved event booking details.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 booking_id:
 *                   type: integer
 *                   description: Unique ID of the booking.
 *                   example: 12
 *                 event_id:
 *                   type: integer
 *                   description: The event associated with the booking.
 *                   example: 5
 *                 member_code:
 *                   type: string
 *                   description: Code of the member who booked the event.
 *                   example: MBR1024
 *                 event_title:
 *                   type: string
 *                   description: Title of the booked event.
 *                   example: AI Innovations Summit 2025
 *                 booking_status:
 *                   type: string
 *                   description: Current booking status.
 *                   example: Confirmed
 *                 booking_date:
 *                   type: string
 *                   format: date-time
 *                   description: Date and time when the booking was made.
 *                   example: 2025-11-07T11:00:00Z
 *       400:
 *         description: Missing booking ID in request parameters.
 *       404:
 *         description: No booking found for the given ID.
 *       500:
 *         description: Server error while retrieving booking information.
 */
router.get("/booked-event/get-by-id/:id", async (req, res) => {
  const { id } = req.params;
  console.log("my  idddd", id)
  if (!id) {
    return res.send({ message: "Id is required", statusCode: 400 });
  }
  const result = await getEventBookingById(id);
  return res.send(result);
});










export default router;
