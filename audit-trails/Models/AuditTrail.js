import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const AuditTrail = sequelize.define(
    "AuditTrail",
    {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        user_id: {
            type: DataTypes.INTEGER,
            allowNull: true, // Optional for unauthenticated actions if any
        },
        action: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        details: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        ip_address: {
            type: DataTypes.STRING,
            allowNull: true,
        },
    },
    {
        tableName: "audit_trails",
        timestamps: true,
        updatedAt: false,
    }
);

export default AuditTrail;
