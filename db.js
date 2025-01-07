const mysql = require("mysql2");

const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "", 
    database: "chat_app"
});

module.exports = db.promise();
