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

        // Start seeding
        console.log('Starting optimized seeding process...');
        const startTime = Date.now();

        // 1. Process Counties
        console.log('Processing counties...');
        const countyRecords = data.map(c => ({
            code: c.county_code.toString().padStart(3, '0'),
            name: c.county_name.trim().toUpperCase()
        }));

        // Bulk create counties, ignore duplicates or update name if code exists
        await County.bulkCreate(countyRecords, {
            updateOnDuplicate: ['name'],
            individualHooks: false
        });

        const countiesInDb = await County.findAll({ attributes: ['id', 'code'] });
        const countyMap = new Map(countiesInDb.map(c => [c.code, c.id]));

        // 2. Process Subcounties (Constituencies)
        console.log('Processing subcounties...');
        const subcountyRecords = [];
        data.forEach(countyData => {
            const countyId = countyMap.get(countyData.county_code.toString().padStart(3, '0'));
            if (!countyId) return;

            countyData.constituencies.forEach(sc => {
                subcountyRecords.push({
                    name: sc.constituency_name.trim().toLowerCase(),
                    county_id: countyId
                });
            });
        });

        // Use a transaction for the bulk subcounty and ward steps to ensure consistency
        await sequelize.transaction(async (t) => {
            // Bulk create subcounties
            // Since we don't have a unique constraint on subcounty name per se in the DB schema 
            // (other than what we might want), we'll do this carefully.
            // Note: If the user hasn't added a unique index, bulkCreate might add duplicates if run twice.
            // We'll filter existing ones first to be safe and truly fast.
            const existingSubcounties = await Subcounty.findAll({ attributes: ['name', 'county_id'], transaction: t });
            const existingSubMap = new Set(existingSubcounties.map(s => `${s.county_id}_${s.name.toLowerCase()}`));

            const newSubcounties = subcountyRecords.filter(s => !existingSubMap.has(`${s.county_id}_${s.name}`));

            if (newSubcounties.length > 0) {
                console.log(`Adding ${newSubcounties.length} new subcounties...`);
                await Subcounty.bulkCreate(newSubcounties, { transaction: t });
            }

            const allSubcounties = await Subcounty.findAll({ attributes: ['id', 'name', 'county_id'], transaction: t });
            const subcountyMap = new Map(allSubcounties.map(s => [`${s.county_id}_${s.name.toLowerCase()}`, s.id]));

            // 3. Process Wards
            console.log('Processing wards...');
            const wardRecords = [];
            data.forEach(countyData => {
                const countyId = countyMap.get(countyData.county_code.toString().padStart(3, '0'));

                countyData.constituencies.forEach(sc => {
                    const subcountyId = subcountyMap.get(`${countyId}_${sc.constituency_name.trim().toLowerCase()}`);
                    if (!subcountyId) return;

                    sc.wards.forEach(w => {
                        wardRecords.push({
                            name: w.trim().toLowerCase(),
                            subcounty_id: subcountyId
                        });
                    });
                });
            });

            const existingWards = await Ward.findAll({ attributes: ['name', 'subcounty_id'], transaction: t });
            const existingWardMap = new Set(existingWards.map(w => `${w.subcounty_id}_${w.name.toLowerCase()}`));

            const newWards = wardRecords.filter(w => !existingWardMap.has(`${w.subcounty_id}_${w.name}`));

            if (newWards.length > 0) {
                console.log(`Adding ${newWards.length} new wards...`);
                // Split bulk create into chunks of 500 to avoid packet size limits
                const chunkSize = 500;
                for (let i = 0; i < newWards.length; i += chunkSize) {
                    const chunk = newWards.slice(i, i + chunkSize);
                    await Ward.bulkCreate(chunk, { transaction: t });
                    console.log(`  Inserted wards ${i + 1} to ${Math.min(i + chunkSize, newWards.length)}`);
                }
            }
        });

        const duration = ((Date.now() - startTime) / 1000).toFixed(2);
        console.log(`Full location hierarchy seeded successfully in ${duration}s!`);
        process.exit(0);
    } catch (error) {
        console.error('Error seeding full data:', error);
        process.exit(1);
    }
}

seedFull();
