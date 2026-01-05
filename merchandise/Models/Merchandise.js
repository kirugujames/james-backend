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
        price: {
            type: DataTypes.DECIMAL(10, 2),
            allowNull: false,
        },
        stock_quantity: {
            type: DataTypes.INTEGER,
            defaultValue: 0,
        },
        image: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        status: {
            type: DataTypes.ENUM("available", "out_of_stock", "discontinued"),
            defaultValue: "available",
        },
    },
    {
        tableName: "merchandise",
        timestamps: true,
    }
);

export default Merchandise;
