// Script to parse and format Kenya location data for bulk insertion

// Counties data (47 counties)
const countiesData = {
    "counties": [
        { "name": "MOMBASA", "code": "001" },
        { "name": "KWALE", "code": "002" },
        { "name": "KILIFI", "code": "003" },
        { "name": "TANA RIVER", "code": "004" },
        { "name": "LAMU", "code": "005" },
        { "name": "TAITA TAVETA", "code": "006" },
        { "name": "GARISSA", "code": "007" },
        { "name": "WAJIR", "code": "008" },
        { "name": "MANDERA", "code": "009" },
        { "name": "MARSABIT", "code": "010" },
        { "name": "ISIOLO", "code": "011" },
        { "name": "MERU", "code": "012" },
        { "name": "THARAKA-NITHI", "code": "013" },
        { "name": "EMBU", "code": "014" },
        { "name": "KITUI", "code": "015" },
        { "name": "MACHAKOS", "code": "016" },
        { "name": "MAKUENI", "code": "017" },
        { "name": "NYANDARUA", "code": "018" },
        { "name": "NYERI", "code": "019" },
        { "name": "KIRINYAGA", "code": "020" },
        { "name": "MURANG'A", "code": "021" },
        { "name": "KIAMBU", "code": "022" },
        { "name": "TURKANA", "code": "023" },
        { "name": "WEST POKOT", "code": "024" },
        { "name": "SAMBURU", "code": "025" },
        { "name": "TRANS NZOIA", "code": "026" },
        { "name": "UASIN GISHU", "code": "027" },
        { "name": "ELGEYO/MARAKWET", "code": "028" },
        { "name": "NANDI", "code": "029" },
        { "name": "BARINGO", "code": "030" },
        { "name": "LAIKIPIA", "code": "031" },
        { "name": "NAKURU", "code": "032" },
        { "name": "NAROK", "code": "033" },
        { "name": "KAJIADO", "code": "034" },
        { "name": "KERICHO", "code": "035" },
        { "name": "BOMET", "code": "036" },
        { "name": "KAKAMEGA", "code": "037" },
        { "name": "VIHIGA", "code": "038" },
        { "name": "BUNGOMA", "code": "039" },
        { "name": "BUSIA", "code": "040" },
        { "name": "SIAYA", "code": "041" },
        { "name": "KISUMU", "code": "042" },
        { "name": "HOMA BAY", "code": "043" },
        { "name": "MIGORI", "code": "044" },
        { "name": "KISII", "code": "045" },
        { "name": "NYAMIRA", "code": "046" },
        { "name": "NAIROBI", "code": "047" }
    ]
};

// Sample subcounties (constituencies) - showing first few from the data
// Note: You'll need to map county names to IDs after inserting counties
const subcountiesData = {
    "subcounties": [
        { "name": "changamwe", "county_id": 1 },
        { "name": "jomvu", "county_id": 1 },
        { "name": "kisauni", "county_id": 1 },
        { "name": "nyali", "county_id": 1 },
        { "name": "likoni", "county_id": 1 },
        { "name": "mvita", "county_id": 1 },
        { "name": "msambweni", "county_id": 2 },
        { "name": "lungalunga", "county_id": 2 },
        { "name": "matuga", "county_id": 2 },
        { "name": "kinango", "county_id": 2 }
        // ... more subcounties
    ]
};

// Sample wards - showing first few from the data
// Note: You'll need to map constituency names to IDs after inserting subcounties
const wardsData = {
    "wards": [
        { "name": "port reitz", "subcounty_id": 1 },
        { "name": "kipevu", "subcounty_id": 1 },
        { "name": "airport", "subcounty_id": 1 },
        { "name": "changamwe", "subcounty_id": 1 },
        { "name": "chaani", "subcounty_id": 1 },
        { "name": "jomvu kuu", "subcounty_id": 2 },
        { "name": "miritini", "subcounty_id": 2 },
        { "name": "mikindani", "subcounty_id": 2 }
        // ... more wards
    ]
};

console.log("Counties JSON:");
console.log(JSON.stringify(countiesData, null, 2));

export { countiesData, subcountiesData, wardsData };
