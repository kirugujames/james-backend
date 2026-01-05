import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const County = sequelize.define(
    "County",
    {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        name: {
            type: DataTypes.STRING,
            allowNull: false,
            unique: true,
        },
        code: {
            type: DataTypes.STRING(10),
            allowNull: true,
            unique: true,
        },
    },
    {
        tableName: "counties",
        timestamps: true,
    }
);

export default County;
