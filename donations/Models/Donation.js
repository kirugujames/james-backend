import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const Donation = sequelize.define(
    "Donation",
    {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        amount: {
            type: DataTypes.DECIMAL(10, 2),
            allowNull: false,
        },
        type: {
            type: DataTypes.ENUM("electronic", "cash"),
            allowNull: false,
        },
        member_id: {
            type: DataTypes.INTEGER,
            allowNull: true, // Optional for non-member donations
        },
        donor_name: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        donor_email: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        transaction_id: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        date: {
            type: DataTypes.DATE,
            defaultValue: DataTypes.NOW,
        },
        notes: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
    },
    {
        tableName: "donations",
        timestamps: true,
    }
);

export default Donation;
