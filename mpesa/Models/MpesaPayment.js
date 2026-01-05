import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const MpesaPayment = sequelize.define(
    "MpesaPayment",
    {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        phone_number: {
            type: DataTypes.STRING(15),
            allowNull: false,
        },
        amount: {
            type: DataTypes.DECIMAL(10, 2),
            allowNull: false,
        },
        account_reference: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        transaction_desc: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        merchant_request_id: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        checkout_request_id: {
            type: DataTypes.STRING,
            allowNull: true,
            unique: true,
        },
        result_code: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        result_desc: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        mpesa_receipt_number: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        transaction_date: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        status: {
            type: DataTypes.ENUM("pending", "completed", "failed", "cancelled"),
            defaultValue: "pending",
        },
    },
    {
        tableName: "mpesa_payments",
        timestamps: true,
    }
);

export default MpesaPayment;
