import sequelize from "../database/database.js";
import County from "../locations/Models/County.js";
import Subcounty from "../locations/Models/Subcounty.js";
import Ward from "../locations/Models/Ward.js";

async function verify() {
    try {
        const kakamega = await County.findOne({ where: { code: '037' } });
        if (!kakamega) {
            console.log('Kakamega not found.');
            process.exit(1);
        }
        console.log(`Found County: ${kakamega.name} (ID: ${kakamega.id})`);

        const subcounties = await Subcounty.findAll({ where: { county_id: kakamega.id } });
        console.log(`Subcounties for Kakamega (${subcounties.length}):`);
        subcounties.forEach(s => console.log(` - ${s.name}`));

        if (subcounties.length > 0) {
            const firstSub = subcounties[0];
            const wards = await Ward.findAll({ where: { subcounty_id: firstSub.id } });
            console.log(`Wards for ${firstSub.name} (${wards.length}):`);
            wards.forEach(w => console.log(`   * ${w.name}`));
        }

        process.exit(0);
    } catch (error) {
        console.error('Verification failed:', error);
        process.exit(1);
    }
}

verify();
