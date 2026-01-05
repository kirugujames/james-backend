import PoliticalApp from "./Models/PoliticalApp.js";

// Create Application (User)
export async function createApplication(req) {
    const { position_name, position, details } = req.body;
    const user_id = req.user.id;
    const appPosition = position_name || position;
    try {
        const app = await PoliticalApp.create({ user_id, position_name: appPosition, details });
        return { statusCode: 201, message: "Application submitted successfully", data: app };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get All Applications (Admin)
export async function getAllApplications() {
    try {
        const apps = await PoliticalApp.findAll();
        return { statusCode: 200, message: "Applications fetched successfully", data: apps };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Approve/Reject Application (Admin)
export async function updateApplicationStatus(req) {
    const { id, applicationId, status, admin_notes } = req.body;
    const appId = id || applicationId;
    try {
        const app = await PoliticalApp.findByPk(appId);
        if (!app) return { statusCode: 404, message: "Application not found", data: null };
        await app.update({ status, admin_notes });
        return { statusCode: 200, message: `Application ${status} successfully`, data: app };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}
