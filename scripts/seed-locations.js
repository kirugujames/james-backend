import fs from 'fs';
import path from 'path';
import sequelize from '../database/database.js';
import County from '../locations/Models/County.js';
import Subcounty from '../locations/Models/Subcounty.js';

const __dirname = path.resolve();

const countiesPath = path.join(__dirname, 'locations', 'data', 'counties.json');
const subcountiesPath = path.join(__dirname, 'locations', 'data', 'subcounties-partial.json');

async function seed() {
    try {
        // Authenticate database
        await sequelize.authenticate();
        console.log('Database connected.');

        // Read files
        const countiesData = JSON.parse(fs.readFileSync(countiesPath, 'utf8'));
        const subcountiesData = JSON.parse(fs.readFileSync(subcountiesPath, 'utf8'));

        console.log('Seeding counties...');
        for (const item of countiesData.counties) {
            await County.findOrCreate({
                where: { name: item.name },
                defaults: { code: item.code }
            });
        }
        console.log('Counties seeded.');

        console.log('Seeding subcounties...');
        for (const item of subcountiesData.subcounties) {
            // Find the county to get its ID (though the JSON already has county_id)
            // But we should be careful about IDs alignment
            await Subcounty.findOrCreate({
                where: { name: item.name, county_id: item.county_id }
            });
        }
        console.log('Subcounties seeded.');

        console.log('Seeding completed successfully.');
        process.exit(0);
    } catch (error) {
        console.error('Error seeding data:', error);
        process.exit(1);
    }
}

seed();
