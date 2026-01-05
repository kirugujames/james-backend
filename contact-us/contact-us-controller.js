import ContactUs from "./Models/ContactUs.js";

// Submit Contact (User)
export async function submitContact(req) {
    const { name, email, subject, message } = req.body;
    try {
        const contact = await ContactUs.create({ name, email, subject, message });
        return { statusCode: 201, message: "Message sent successfully", data: contact };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get All Messages (Admin)
export async function getAllContacts() {
    try {
        const contacts = await ContactUs.findAll();
        return { statusCode: 200, message: "Messages fetched successfully", data: contacts };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}
