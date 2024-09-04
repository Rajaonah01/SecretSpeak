// app.js
const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const db = require('./db'); // Importer la connexion à la base de données
const app = express();
const port = 3000;

// Configurer le middleware de session
app.use(session({
  secret: 'votre_secret_de_session', // Remplacez ceci par une chaîne de caractères unique
  resave: false,
  saveUninitialized: true
}));

// Middleware pour analyser les requêtes JSON
app.use(express.json());

// Servir les fichiers statiques
app.use(express.static(path.join(__dirname, 'public')));

// Route pour l'inscription d'un nouvel utilisateur
app.post('/signup', async (req, res) => {
  const { nom, email, mot_de_passe } = req.body;

  // Vérifier si l'utilisateur existe déjà
  db.query('SELECT * FROM utilisateurs WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.error('Erreur lors de la vérification de l\'utilisateur :', err);
      return res.status(500).send('Erreur du serveur');
    }

    if (results.length > 0) {
      return res.status(409).send('Cet email est déjà utilisé.');
    }

    // Hacher le mot de passe
    const motDePasseHache = await bcrypt.hash(mot_de_passe, 10);

    // Insérer le nouvel utilisateur dans la base de données
    db.query('INSERT INTO utilisateurs (nom, email, mot_de_passe) VALUES (?, ?, ?)', [nom, email, motDePasseHache], (err, result) => {
      if (err) {
        console.error('Erreur lors de l\'ajout de l\'utilisateur :', err);
        return res.status(500).send('Erreur lors de l\'ajout de l\'utilisateur.');
      }
      res.status(201).send('Utilisateur inscrit avec succès.');
    });
  });
});

// Route pour la connexion de l'utilisateur
app.post('/login', (req, res) => {
  const { email, mot_de_passe } = req.body;

  // Vérifier si l'utilisateur existe
  db.query('SELECT * FROM utilisateurs WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération de l\'utilisateur :', err);
      return res.status(500).send('Erreur du serveur');
    }

    if (results.length === 0) {
      return res.status(401).send('Email ou mot de passe incorrect.');
    }

    // Comparer le mot de passe fourni avec le mot de passe haché de la base de données
    const utilisateur = results[0];
    const motDePasseCorrespond = await bcrypt.compare(mot_de_passe, utilisateur.mot_de_passe);

    if (!motDePasseCorrespond) {
      return res.status(401).send('Email ou mot de passe incorrect.');
    }

    // Créer une session pour l'utilisateur
    req.session.utilisateurId = utilisateur.id;
    res.send('Connexion réussie.');
  });
});

// Route pour déconnecter l'utilisateur
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Erreur lors de la déconnexion.');
    }
    res.send('Déconnexion réussie.');
  });
});

// Démarrer le serveur
app.listen(port, () => {
  console.log(`Serveur Express en écoute sur http://localhost:${port}`);
});
