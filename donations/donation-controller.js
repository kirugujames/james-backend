import Donation from "./Models/Donation.js";

// --- INDIVIDUAL DONATIONS ---

// Create Individual Donation
export async function createIndividualDonation(req) {
    const { amount, firstname, lastname, email, phone, is_anonymous } = req.body;
    try {
        const donation = await Donation.create({
            amount,
            firstname,
            lastname,
            email,
            phone,
            is_anonymous,
            type: "individual"
        });
        return { statusCode: 201, message: "Individual donation created successfully", data: donation };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Update Individual Donation
export async function updateIndividualDonation(req) {
    const { id } = req.params;
    const { amount, firstname, lastname, email, phone, is_anonymous } = req.body;
    try {
        const donation = await Donation.findByPk(id);
        if (!donation) return { statusCode: 404, message: "Donation not found", data: null };

        await donation.update({ amount, firstname, lastname, email, phone, is_anonymous });
        return { statusCode: 200, message: "Individual donation updated successfully", data: donation };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get Individual Donations
export async function getIndividualDonations() {
    try {
        const donations = await Donation.findAll({ where: { type: "individual" } });
        return { statusCode: 200, message: "Individual donations fetched", data: donations };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// --- ORGANIZATION DONATIONS ---

// Create Organization Donation
export async function createOrganizationDonation(req) {
    const { amount, organization_name, email, phone, is_anonymous } = req.body;
    try {
        const donation = await Donation.create({
            amount,
            organization_name,
            email,
            phone,
            is_anonymous,
            type: "organization"
        });
        return { statusCode: 201, message: "Organization donation created successfully", data: donation };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Update Organization Donation
export async function updateOrganizationDonation(req) {
    const { id } = req.params;
    const { amount, organization_name, email, phone, is_anonymous } = req.body;
    try {
        const donation = await Donation.findByPk(id);
        if (!donation) return { statusCode: 404, message: "Donation not found", data: null };

        await donation.update({ amount, organization_name, email, phone, is_anonymous });
        return { statusCode: 200, message: "Organization donation updated successfully", data: donation };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get Organization Donations
export async function getOrganizationDonations() {
    try {
        const donations = await Donation.findAll({ where: { type: "organization" } });
        return { statusCode: 200, message: "Organization donations fetched", data: donations };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}
