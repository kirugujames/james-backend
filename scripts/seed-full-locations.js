import axios from 'axios';
import fs from 'fs';
import path from 'path';
import sequelize from '../database/database.js';
import County from '../locations/Models/County.js';
import Subcounty from '../locations/Models/Subcounty.js';
import Ward from '../locations/Models/Ward.js';

const __dirname = path.resolve();
const DATA_URL = 'https://raw.githubusercontent.com/michaelnjuguna/Kenyan-counties-their-subcounties-and-wards-in-json-yaml-mysql-csv-latex-xlsx-Bson-markdown-and-xml/main/county.json';
const OUTPUT_PATH = path.join(__dirname, 'locations', 'data', 'kenya-locations-full.json');

async function seedFull() {
    try {
        console.log('Fetching full location data...');
        const response = await axios.get(DATA_URL);
        const data = response.data;

        // Save for reference
        fs.writeFileSync(OUTPUT_PATH, JSON.stringify(data, null, 2));
        console.log(`Saved full data to ${OUTPUT_PATH}`);

        // Start transaction
        const transaction = await sequelize.transaction();

        try {
            console.log('Seeding full hierarchy...');

            for (const countyData of data) {
                const countyCode = countyData.county_code.toString().padStart(3, '0');
                const [county] = await County.findOrCreate({
                    where: { code: countyCode },
                    defaults: { name: countyData.county_name.trim().toUpperCase() },
                    transaction
                });

                // Update name in case it changed or was normalized differently
                await county.update({ name: countyData.county_name.trim().toUpperCase() }, { transaction });

                for (const subcountyData of countyData.constituencies) {
                    const subcountyName = subcountyData.constituency_name.trim().toLowerCase();
                    const [subcounty] = await Subcounty.findOrCreate({
                        where: {
                            name: subcountyName,
                            county_id: county.id
                        },
                        transaction
                    });

                    for (const wardName of subcountyData.wards) {
                        await Ward.findOrCreate({
                            where: {
                                name: wardName.trim().toLowerCase(),
                                subcounty_id: subcounty.id
                            },
                            transaction
                        });
                    }
                }
            }

            await transaction.commit();
            console.log('Full location hierarchy seeded successfully!');
            process.exit(0);
        } catch (error) {
            await transaction.rollback();
            throw error;
        }
    } catch (error) {
        console.error('Error seeding full data:', error);
        process.exit(1);
    }
}

seedFull();
