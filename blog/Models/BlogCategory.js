import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const BlogCategory = sequelize.define("BlogCategory", {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  category: {
    unique: true,
    type: DataTypes.STRING,
    allowNull: false
  },
  posted_by: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  tableName: "blogCategory",
  timestamps: true
});

export default BlogCategory;
