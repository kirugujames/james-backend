import { DataTypes, Model } from "sequelize";
import sequelize from "../../database/database.js";


class User extends Model { }

User.init(
  {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    username: { type: DataTypes.STRING, allowNull: false, unique: true },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    role_id: { type: DataTypes.INTEGER },
    is_logged_in: { type: DataTypes.BOOLEAN, defaultValue: false },
    session_token: { type: DataTypes.STRING },
    status: { type: DataTypes.ENUM("active", "deactivated"), defaultValue: "active" },
    reset_password_token: { type: DataTypes.STRING },
    reset_password_expires: { type: DataTypes.DATE },
    refresh_token: { type: DataTypes.TEXT },
  },
  {
    sequelize,
    modelName: "User",
    tableName: "user",
    timestamps: false,
  }
);

export default User;
