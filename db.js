// db.js
const mysql = require('mysql2');

// Créer une connexion à la base de données
const connection = mysql.createConnection({
  host: 'localhost',    // Adresse du serveur MySQL (par défaut : localhost)
  user: 'root',         // Nom d'utilisateur MySQL (par exemple : root)
  password: '', // Mot de passe MySQL
  database: 'speaksecret' // Nom de la base de données à utiliser
});

// Connecter à la base de données
connection.connect((err) => {
  if (err) {
    console.error('Erreur de connexion à la base de données :', err.stack);
    return;
  }
  console.log('Connecté à la base de données MySQL avec succès !');
});

module.exports = connection;
