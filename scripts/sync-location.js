import sequelize from "../database/database.js";
import County from "../locations/Models/County.js";
import Subcounty from "../locations/Models/Subcounty.js";
import Ward from "../locations/Models/Ward.js";

(async () => {
    try {
        await sequelize.sync({ alter: true });
        console.log("Location models synced successfully.");
        process.exit(0);
    } catch (error) {
        console.error("Error syncing location models:", error);
        process.exit(1);
    }
})();
