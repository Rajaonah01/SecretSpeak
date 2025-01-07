const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const db = require("./db");
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
    secret: "chat_app_secret",
    resave: false,
    saveUninitialized: false
}));


const users = [];
const messages = [];


app.get("/", (req, res) => {
    res.render("welcome");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    try {
        await db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hashedPassword]);
        res.redirect("/login");
    } catch (error) {
        console.error(error);
        res.redirect("/register");
    }
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
        const user = users[0];
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = { id: user.id, email: user.email };
            return res.redirect("/chat");
        }
        res.redirect("/login");
    } catch (error) {
        console.error(error);
        res.redirect("/login");
    }
});


app.get("/chat", async (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login");
    }
    try {
        const [users] = await db.query("SELECT id, email FROM users WHERE id != ?", [req.session.user.id]);
        res.render("chat", { user: req.session.user, users });
    } catch (error) {
        console.error(error);
        res.redirect("/login");
    }
});


// Socket.io
io.on("connection", (socket) => {
    console.log("Utilisateur connecter");

    socket.on("message", async (data) => {
        const { senderId, receiverId, content } = data;

        try {
            await db.query(
                "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
                [senderId, receiverId, content]
            );
            io.emit("message", data);
        } catch (error) {
            console.error(error);
        }
    });

    socket.on("disconnect", () => {
        console.log("Utilisateur déconnecter");
    });
});
// Server
const PORT = 3000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
