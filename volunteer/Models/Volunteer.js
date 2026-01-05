import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const Volunteer = sequelize.define(
    "Volunteer",
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
        email: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        phone: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        type: {
            type: DataTypes.ENUM("general", "event"),
            defaultValue: "general",
        },
        event_id: {
            type: DataTypes.INTEGER,
            allowNull: true,
        },
        interests: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        status: {
            type: DataTypes.ENUM("pending", "approved", "rejected"),
            defaultValue: "pending",
        },
    },
    {
        tableName: "volunteers",
        timestamps: true,
    }
);

export default Volunteer;
