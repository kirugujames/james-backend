import { DataTypes } from "sequelize";
import sequelize from "../../database/database.js";

const Events = sequelize.define("Events", {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
        allowNull: false
    },
    event_type:{
        type:DataTypes.STRING,
        allowNull: false
    },
    title:{
        type:DataTypes.STRING,
        allowNull: false
    },
    event_date:{
        type:DataTypes.STRING,
        allowNull: false
    },
    from_time:{
        type:DataTypes.STRING,
        allowNull: false
    },
    to_time:{
        type:DataTypes.STRING,
        allowNull: false
    },
    description:{
        type:DataTypes.STRING,
        allowNull: false
    },
    location:{
        type: DataTypes.STRING,
        allowNull: false
    },
    sub_title:{
        type: DataTypes.STRING,
        allowNull: true
    },
    image:{
        type: DataTypes.TEXT('long'),
        allowNull: false
    }
}, {
    tableName: "events",
    timestamps: true
});

export default Events;