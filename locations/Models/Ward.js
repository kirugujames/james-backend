import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const Ward = sequelize.define(
    "Ward",
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
        subcounty_id: {
            type: DataTypes.INTEGER,
            allowNull: false,
            references: {
                model: "subcounties",
                key: "id",
            },
            onDelete: "CASCADE",
            onUpdate: "CASCADE",
        },
    },
    {
        tableName: "wards",
        timestamps: true,
    }
);

export default Ward;
