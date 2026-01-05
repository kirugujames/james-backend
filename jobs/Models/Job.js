import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const Job = sequelize.define(
  "Job",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    job_title: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    posted_by: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    status: {
      type: DataTypes.ENUM("active", "passed"),
      defaultValue: "active",
    },
  },
  {
    tableName: "jobs",
    timestamps: true,
  }
);

export default Job;
