import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const PoliticalApp = sequelize.define(
    "PoliticalApp",
    {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        user_id: {
            type: DataTypes.INTEGER,
            allowNull: false,
        },
        position_name: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        details: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        status: {
            type: DataTypes.ENUM("pending", "approved", "rejected"),
            defaultValue: "pending",
        },
        submission_date: {
            type: DataTypes.DATE,
            defaultValue: DataTypes.NOW,
        },
        admin_notes: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
    },
    {
        tableName: "political_apps",
        timestamps: true,
    }
);

export default PoliticalApp;
