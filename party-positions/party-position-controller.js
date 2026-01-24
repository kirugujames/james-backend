import PartyPosition from "./models/PartyPosition.js";
import { sendEmail } from "../utils/send-email.js";

// Apply for Party position
export async function applyForPartyPosition(req) {
    try {
        const {
            first_name,
            last_name,
            email,
            phone,
            membership_number,
            position
        } = req.body;

        const application = await PartyPosition.create({
            first_name,
            last_name,
            email,
            phone,
            membership_number,
            position,
            status: "Pending" // Default as requested
        });

        return {
            message: "Party position application submitted successfully",
            statusCode: 201,
            data: application
        };
    } catch (error) {
        console.error("Party position apply error:", error);
        return {
            message: error.message || "Internal server error",
            statusCode: 500,
            data: null
        };
    }
}

// Get all applications
export async function getAllPartyPositionApplications() {
    try {
        const applications = await PartyPosition.findAll();
        return {
            message: "Party position applications fetched successfully",
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
export async function getPartyPositionApplicationsByMember(identifier) {
    try {
        const applications = await PartyPosition.findAll({
            where: {
                membership_number: identifier
            }
        });

        return {
            message: "Member's party position applications fetched successfully",
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
export async function updatePartyPositionStatus(req) {
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

        const application = await PartyPosition.findByPk(id);
        if (!application) {
            return {
                message: "Party position application not found",
                statusCode: 404,
                data: null
            };
        }

        await application.update({ status });

        // Send email notification
        try {
            const { email, first_name } = application;
            let emailMessage = `Dear ${first_name},\n\nYour party position application status has been updated to: ${status}.`;

            if (status === 'Rejected' && req.body.reason) {
                emailMessage += `\n\nReason: ${req.body.reason}`;
            }

            emailMessage += `\n\nBest regards,\nParty Administration`;

            await sendEmail({
                to: email,
                subject: `Party Position Application Update: ${status}`,
                message: emailMessage
            });
        } catch (emailError) {
            console.error("Failed to send status update email:", emailError);
        }

        return {
            message: `Party position application status updated to ${status} successfully`,
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
