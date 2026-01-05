import Merchandise from "./Models/Merchandise.js";

// Create Merchandise
export async function createMerch(req) {
    const { name, description, price, stock_quantity, image } = req.body;
    try {
        const merch = await Merchandise.create({ name, description, price, stock_quantity, image });
        return { statusCode: 201, message: "Merchandise created successfully", data: merch };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Get All Merch
export async function getAllMerch() {
    try {
        const merch = await Merchandise.findAll();
        return { statusCode: 200, message: "Merchandise fetched successfully", data: merch };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Update Merch
export async function updateMerch(req) {
    const { id } = req.params;
    try {
        const merch = await Merchandise.findByPk(id);
        if (!merch) return { statusCode: 404, message: "Merchandise not found", data: null };
        await merch.update(req.body);
        return { statusCode: 200, message: "Merchandise updated successfully", data: merch };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}

// Delete Merch
export async function deleteMerch(req) {
    const { id } = req.params;
    try {
        const merch = await Merchandise.findByPk(id);
        if (!merch) return { statusCode: 404, message: "Merchandise not found", data: null };
        await merch.destroy();
        return { statusCode: 200, message: "Merchandise deleted successfully", data: null };
    } catch (err) {
        return { statusCode: 500, message: err.message, data: null };
    }
}
