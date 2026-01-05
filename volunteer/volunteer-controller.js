import Volunteer from "./Models/Volunteer.js";

// Sign Up (User)
export async function signUpVolunteer(req) {
    const { name, email, phone, type, event_id, interests } = req.body;
    try {
        const volunteer = await Volunteer.create({ name, email, phone, type, event_id, interests });
        return { statusCode: 201, message: "Volunteer sign up successful", data: volunteer };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get All Volunteers (Admin)
export async function getAllVolunteers() {
    try {
        const volunteers = await Volunteer.findAll();
        return { statusCode: 200, message: "Volunteers fetched successfully", data: volunteers };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get Volunteers by Event ID (Admin)
export async function getVolunteersByEvent(req) {
    const { event_id } = req.params;
    try {
        const volunteers = await Volunteer.findAll({ where: { event_id } });
        return { statusCode: 200, message: "Volunteers for event fetched successfully", data: volunteers };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}
