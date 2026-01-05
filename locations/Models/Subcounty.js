import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const Subcounty = sequelize.define(
    "Subcounty",
    {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        name: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        county_id: {
            type: DataTypes.INTEGER,
            allowNull: false,
            references: {
                model: "counties",
                key: "id",
            },
            onDelete: "CASCADE",
            onUpdate: "CASCADE",
        },
    },
    {
        tableName: "subcounties",
        timestamps: true,
    }
);

export default Subcounty;
