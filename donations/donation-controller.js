import Donation from "./Models/Donation.js";

// Create Donation (Electronic)
export async function createElectronicDonation(req) {
    const { amount, transaction_id, member_id, donor_name, donor_email, notes } = req.body;
    try {
        const donation = await Donation.create({
            amount,
            type: "electronic",
            transaction_id,
            member_id,
            donor_name,
            donor_email,
            notes,
        });
        return { statusCode: 201, message: "Donation recorded successfully", data: donation };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Create Donation (Manual/Cash)
export async function createCashDonation(req) {
    const { amount, donor_name, donor_email, notes, member_id } = req.body;
    try {
        const donation = await Donation.create({
            amount,
            type: "cash",
            member_id,
            donor_name,
            donor_email,
            notes,
        });
        return { statusCode: 201, message: "Cash donation recorded successfully", data: donation };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get All Donations
export async function getAllDonations() {
    try {
        const donations = await Donation.findAll();
        return { statusCode: 200, message: "Donations fetched successfully", data: donations };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}
