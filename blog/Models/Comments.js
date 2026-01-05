import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const Comment = sequelize.define("Comment", {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },

  blog_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },

  commenter_name: {
    type: DataTypes.STRING,
    allowNull: false
  },

  message: {
    type: DataTypes.TEXT,
    allowNull: false
  }
}, {
  tableName: "comments",
  timestamps: true
});

export default Comment;
