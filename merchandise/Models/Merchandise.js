import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const Merchandise = sequelize.define(
    "Merchandise",
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
        description: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        category: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        price: {
            type: DataTypes.DECIMAL(10, 2),
            allowNull: false,
        },
        stock_quantity: {
            type: DataTypes.INTEGER,
            defaultValue: 0,
        },
        size: {
            type: DataTypes.JSON,
            defaultValue: [],
            allowNull: true,
        },
        image: {
            type: DataTypes.TEXT, // Changed to TEXT to support large base64 strings
            allowNull: true,
        },
        status: {
            type: DataTypes.STRING, // Changed to STRING to check for "ACTIVE" or ENUM if preferred, keeping simple for now or adding ACTIVE
            defaultValue: "ACTIVE",
        },
    },
    {
        tableName: "merchandise",
        timestamps: true,
    }
);

export default Merchandise;
