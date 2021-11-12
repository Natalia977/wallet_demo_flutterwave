const mongoose = require("mongoose");

const { MONGO_URI } = process.env;

exports.connect = () => {
    //coneccion a la BD
    mongoose
    .connect(MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => {
        console.log("Successfully connected to database");
    })
    .catch((error) => {
        console.log("Database connection failed. Exiting now...");
        console.log(error);
        process.exit(1);
    });
};