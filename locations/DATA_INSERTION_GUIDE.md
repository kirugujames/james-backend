# Kenya Location Data Insertion Guide

## Step 1: Insert Counties

Use this JSON with the `POST /api/locations/counties/bulk` endpoint:

```json
{
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
}
```

## Step 2: Get the Complete Data

I see you have the data in a table format. To properly insert subcounties and wards, I need the complete dataset.

**Can you provide the data in one of these formats:**

### Option 1: Excel/CSV File
Upload the Excel or CSV file with columns: `id`, `County`, `Constituency_name`, `Ward`

### Option 2: Complete Text List
Share the complete list (you showed rows 1-181, but there should be more)

### Option 3: I'll Create a Parser
If you can share the complete raw data, I'll create a script to parse it and generate the proper JSON files for subcounties and wards.

## What I've Observed from Your Data

From rows 1-181:
- **Counties**: 47 total (rows 1-47 have county names only)
- **Wards**: Rows 48-181 show wards with their constituencies

The pattern shows:
- Column 1: Ward ID
- Column 2: County ID (1-8 visible so far)
- Column 3: Constituency name (subcounty)
- Column 4: Ward name

## Next Steps

1. **Insert counties first** using the JSON above via Swagger UI
2. **Share the complete dataset** so I can prepare the subcounties and wards JSON
3. I'll create properly formatted JSON files for you to insert

Would you like to share the complete dataset, or should I create a script that you can run to parse your data file?
