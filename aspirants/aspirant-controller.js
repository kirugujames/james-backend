import Aspirant_Application from "./models/Aspirant-Application.js";
import { sendEmail } from "../utils/send-email.js";

// Apply for Aspirant position
export async function applyForAspirant(req) {
    try {
        const {
            first_name,
            last_name,
            email,
            phone,
            membership_number,
            position
        } = req.body;

        const application = await Aspirant_Application.create({
            first_name,
            last_name,
            email,
            phone,
            membership_number,
            position,
            status: "Pending" // Default as requested
        });

        return {
            message: "Aspirant application submitted successfully",
            statusCode: 201,
            data: application
        };
    } catch (error) {
        console.error("Aspirant apply error:", error);
        return {
            message: error.message || "Internal server error",
            statusCode: 500,
            data: null
        };
    }
}

// Get all applications
export async function getAllAspirantApplications() {
    try {
        const applications = await Aspirant_Application.findAll();
        return {
            message: "Aspirant applications fetched successfully",
            statusCode: 200,
            data: applications
        };
    } catch (error) {
        return {
            message: error.message,
            statusCode: 500,
            data: null
        };
    }
}

// Get by member number or code
export async function getAspirantApplicationsByMember(identifier) {
    try {
        const applications = await Aspirant_Application.findAll({
            where: {
                membership_number: identifier
            }
        });

        return {
            message: "Member's aspirant applications fetched successfully",
            statusCode: 200,
            data: applications
        };
    } catch (error) {
        return {
            message: error.message,
            statusCode: 500,
            data: null
        };
    }
}

// Update application status
export async function updateAspirantStatus(req) {
    try {
        const { id, status } = req.body;

        const validStatuses = ["Pending", "Approved", "Rejected", "Under Review"];
        if (!validStatuses.includes(status)) {
            return {
                message: "Invalid status value",
                statusCode: 400,
                data: null
            };
        }

        const application = await Aspirant_Application.findByPk(id);
        if (!application) {
            return {
                message: "Aspirant application not found",
                statusCode: 404,
                data: null
            };
        }

        await application.update({ status });

        // Send email notification
        try {
            const { email, first_name } = application;
            let emailMessage = `Dear ${first_name},\n\nYour aspirant application status has been updated to: ${status}.`;

            if (status === 'Rejected' && req.body.reason) {
                emailMessage += `\n\nReason: ${req.body.reason}`;
            }

            emailMessage += `\n\nBest regards,\nParty Administration`;

            await sendEmail({
                to: email,
                subject: `Aspirant Application Update: ${status}`,
                message: emailMessage
            });
        } catch (emailError) {
            console.error("Failed to send status update email:", emailError);
        }

        return {
            message: `Aspirant application status updated to ${status} successfully`,
            statusCode: 200,
            data: application
        };
    } catch (error) {
        return {
            message: error.message,
            statusCode: 500,
            data: null
        };
    }
}
