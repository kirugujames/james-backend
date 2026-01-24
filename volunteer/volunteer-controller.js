import Volunteer from "./Models/Volunteer.js";
import Event from "../events/Models/Event.js";
import { sendEmail } from "../utils/send-email.js";

// Sign Up (User)
export async function signUpVolunteer(req) {
    const { first_name, last_name, email, phone, volunteer_type, event_id, event_name, areas_of_interest, consent } = req.body;
    try {
        // const event_id_val = volunteer_type === "event" ? event_id : null; 
        // User passes event_id directly now per request sample
        const volunteer = await Volunteer.create({
            first_name,
            last_name,
            email,
            phone,
            volunteer_type,
            event_id,
            event_name,
            areas_of_interest,
            consent
        });
        return { statusCode: 201, message: "Volunteer sign up successful", data: volunteer };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get All Volunteers (Admin)
export async function getAllVolunteers() {
    try {
        const volunteers = await Volunteer.findAll({
            include: [{
                model: Event,
                attributes: ['id', 'title']
            }]
        });
        return { statusCode: 200, message: "Volunteers fetched successfully", data: volunteers };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get Volunteers by Event (Admin)
export async function getVolunteersByEvent(req) {
    const { event_id } = req.params;
    try {
        const volunteers = await Volunteer.findAll({
            where: { event_id },
            include: [{
                model: Event,
                attributes: ['id', 'title']
            }]
        });
        return { statusCode: 200, message: "Volunteers for event fetched successfully", data: volunteers };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Update Volunteer Status
export async function updateVolunteerStatus(req) {
    const { id, status } = req.body;
    try {
        const volunteer = await Volunteer.findByPk(id);
        if (!volunteer) return { statusCode: 404, message: "Volunteer not found", data: null };

        await volunteer.update({ status: status.toLowerCase() }); // ensuring lower case for enum

        // Send email notification
        try {
            const { email, first_name } = volunteer;
            let emailMessage = `Dear ${first_name},\n\nYour volunteer application status has been updated to: ${status}.`;

            if (status.toLowerCase() === 'rejected' && req.body.reason) {
                emailMessage += `\n\nReason: ${req.body.reason}`;
            }

            emailMessage += `\n\nBest regards,\nVolunteer Coordination Team`;

            await sendEmail({
                to: email,
                subject: `Volunteer Application Update: ${status}`,
                message: emailMessage
            });
        } catch (emailError) {
            console.error("Failed to send status update email:", emailError);
        }

        return { statusCode: 200, message: `Volunteer status updated to ${status}`, data: volunteer };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}
