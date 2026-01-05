import AuditTrail from "./Models/AuditTrail.js";

// Log Action Utility
export async function logAction(user_id, action, details, ip_address) {
    try {
        await AuditTrail.create({ user_id, action, details, ip_address });
    } catch (err) {
        console.error("Failed to log audit trail:", err.message);
    }
}

// Get All Audit Trails (Admin)
export async function getAllAuditTrails() {
    try {
        const trails = await AuditTrail.findAll();
        return { statusCode: 200, message: "Audit trails fetched successfully", data: trails };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}
