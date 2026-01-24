import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const JobApplication = sequelize.define(
    "JobApplication",
    {
        id: {
            type: DataTypes.INTEGER,
            autoIncrement: true,
            primaryKey: true,
        },
        job_id: {
            type: DataTypes.INTEGER,
            allowNull: false,
        },
        first_name: {
            type: DataTypes.STRING,
            allowNull: false,
            defaultValue: ""
        },
        last_name: {
            type: DataTypes.STRING,
            allowNull: false,
            defaultValue: ""
        },
        email: {
            type: DataTypes.STRING,
            allowNull: false,
            validate: {
                isEmail: true,
            },
        },
        phone: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        document: {
            type: DataTypes.TEXT("long"),
            allowNull: true,
        },
        cover_letter: {
            type: DataTypes.TEXT("long"),
            allowNull: true,
        },
        status: {
            type: DataTypes.ENUM("Pending", "Reviewed", "Shortlisted", "Rejected", "Accepted"),
            defaultValue: "Pending",
        },
    },
    {
        tableName: "job_applications",
        timestamps: true,
    }
);

export default JobApplication;
