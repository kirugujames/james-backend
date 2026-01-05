import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const MemberRegistration = sequelize.define(
  "memberRegistration",
  {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },

    first_name: {
      type: DataTypes.STRING,
      allowNull: false,
    },

    last_name: {
      type: DataTypes.STRING,
      allowNull: false,
    },

    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },

    dob: {
      type: DataTypes.DATEONLY,
      allowNull: false,
    },

    gender: {
      type: DataTypes.STRING,
      allowNull: false,
    },

    phone: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },

    doc_type: {
      type: DataTypes.STRING,
      allowNull: false,
    },

    idNo: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },

    county: {
      type: DataTypes.STRING,
      allowNull: false,
    },

    constituency: {
      type: DataTypes.STRING,
      allowNull: false,
    },

    ward: {
      type: DataTypes.STRING,
      allowNull: false,
    },

    area_of_interest: {
      type: DataTypes.STRING,
      allowNull: false,
    },

    member_code: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    status: {
      type: DataTypes.ENUM("active", "withdrawn"),
      defaultValue: "active",
    },
    is_paid: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    transaction_id: {
      type: DataTypes.STRING,
      allowNull: true,
    },
  },
  {
    tableName: "memberRegistration",
    timestamps: false,
  }
);

export default MemberRegistration;
