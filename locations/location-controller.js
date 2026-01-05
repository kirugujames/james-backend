import County from "./Models/County.js";
import Subcounty from "./Models/Subcounty.js";
import Ward from "./Models/Ward.js";

/**
 * Get all counties
 * @returns {Object} Response object
 */
export async function getAllCounties() {
    try {
        const counties = await County.findAll({
            order: [["name", "ASC"]],
        });

        return {
            statusCode: 200,
            message: "Counties fetched successfully",
            data: counties,
        };
    } catch (error) {
        console.error("Error fetching counties:", error);
        return {
            statusCode: 500,
            message: "Failed to fetch counties",
            data: null,
        };
    }
}

/**
 * Get subcounties by county ID
 * @param {Object} req - Express request object
 * @returns {Object} Response object
 */
export async function getSubcountiesByCounty(req) {
    const { countyId } = req.params;

    try {
        const county = await County.findByPk(countyId);

        if (!county) {
            return {
                statusCode: 404,
                message: "County not found",
                data: null,
            };
        }

        const subcounties = await Subcounty.findAll({
            where: { county_id: countyId },
            order: [["name", "ASC"]],
        });

        return {
            statusCode: 200,
            message: "Subcounties fetched successfully",
            data: subcounties,
        };
    } catch (error) {
        console.error("Error fetching subcounties:", error);
        return {
            statusCode: 500,
            message: "Failed to fetch subcounties",
            data: null,
        };
    }
}

/**
 * Get wards by subcounty ID
 * @param {Object} req - Express request object
 * @returns {Object} Response object
 */
export async function getWardsBySubcounty(req) {
    const { subcountyId } = req.params;

    try {
        const subcounty = await Subcounty.findByPk(subcountyId);

        if (!subcounty) {
            return {
                statusCode: 404,
                message: "Subcounty not found",
                data: null,
            };
        }

        const wards = await Ward.findAll({
            where: { subcounty_id: subcountyId },
            order: [["name", "ASC"]],
        });

        return {
            statusCode: 200,
            message: "Wards fetched successfully",
            data: wards,
        };
    } catch (error) {
        console.error("Error fetching wards:", error);
        return {
            statusCode: 500,
            message: "Failed to fetch wards",
            data: null,
        };
    }
}

/**
 * Bulk insert counties (Admin only)
 * @param {Object} req - Express request object
 * @returns {Object} Response object
 */
export async function bulkInsertCounties(req) {
    const { counties } = req.body;

    if (!counties || !Array.isArray(counties) || counties.length === 0) {
        return {
            statusCode: 400,
            message: "Counties array is required",
            data: null,
        };
    }

    try {
        const createdCounties = await County.bulkCreate(counties, {
            validate: true,
            ignoreDuplicates: true,
        });

        return {
            statusCode: 201,
            message: `${createdCounties.length} counties inserted successfully`,
            data: createdCounties,
        };
    } catch (error) {
        console.error("Error inserting counties:", error);
        return {
            statusCode: 500,
            message: error.message || "Failed to insert counties",
            data: null,
        };
    }
}

/**
 * Bulk insert subcounties (Admin only)
 * @param {Object} req - Express request object
 * @returns {Object} Response object
 */
export async function bulkInsertSubcounties(req) {
    const { subcounties } = req.body;

    if (!subcounties || !Array.isArray(subcounties) || subcounties.length === 0) {
        return {
            statusCode: 400,
            message: "Subcounties array is required",
            data: null,
        };
    }

    try {
        const createdSubcounties = await Subcounty.bulkCreate(subcounties, {
            validate: true,
            ignoreDuplicates: true,
        });

        return {
            statusCode: 201,
            message: `${createdSubcounties.length} subcounties inserted successfully`,
            data: createdSubcounties,
        };
    } catch (error) {
        console.error("Error inserting subcounties:", error);
        return {
            statusCode: 500,
            message: error.message || "Failed to insert subcounties",
            data: null,
        };
    }
}

/**
 * Bulk insert wards (Admin only)
 * @param {Object} req - Express request object
 * @returns {Object} Response object
 */
export async function bulkInsertWards(req) {
    const { wards } = req.body;

    if (!wards || !Array.isArray(wards) || wards.length === 0) {
        return {
            statusCode: 400,
            message: "Wards array is required",
            data: null,
        };
    }

    try {
        const createdWards = await Ward.bulkCreate(wards, {
            validate: true,
            ignoreDuplicates: true,
        });

        return {
            statusCode: 201,
            message: `${createdWards.length} wards inserted successfully`,
            data: createdWards,
        };
    } catch (error) {
        console.error("Error inserting wards:", error);
        return {
            statusCode: 500,
            message: error.message || "Failed to insert wards",
            data: null,
        };
    }
}
