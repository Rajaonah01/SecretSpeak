const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const db = require('./db');
const app = express();
const port = 3000;

app.use(session({
  secret: 'votre_secret_de_session', 
  resave: false,
  saveUninitialized: true
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/signup', async (req, res) => {
  const { nom, email, mot_de_passe } = req.body;
  db.query('SELECT * FROM utilisateurs WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).send('Erreur du serveur');
    if (results.length > 0) return res.status(409).send('Cet email est déjà utilisé.');

    const motDePasseHache = await bcrypt.hash(mot_de_passe, 10);
    db.query('INSERT INTO utilisateurs (nom, email, mot_de_passe) VALUES (?, ?, ?)', [nom, email, motDePasseHache], (err, result) => {
      if (err) return res.status(500).send('Erreur lors de l\'ajout de l\'utilisateur.');
      res.status(201).send('Utilisateur inscrit avec succès.');
    });
  });
});

app.post('/login', (req, res) => {
  const { email, mot_de_passe } = req.body;
  db.query('SELECT * FROM utilisateurs WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).send('Erreur du serveur');
    if (results.length === 0) return res.status(401).send('Email ou mot de passe incorrect.');

    const utilisateur = results[0];
    const motDePasseCorrespond = await bcrypt.compare(mot_de_passe, utilisateur.mot_de_passe);
    if (!motDePasseCorrespond) return res.status(401).send('Email ou mot de passe incorrect.');

    req.session.utilisateurId = utilisateur.id;
    res.send('Connexion réussie.');
  });
});

app.post('/send-message', (req, res) => {
  const { destinataireEmail, message } = req.body;
  const expediteurId = req.session.utilisateurId;

  if (!expediteurId) return res.status(401).send('Vous devez être connecté pour envoyer un message.');

  db.query('SELECT id FROM utilisateurs WHERE email = ?', [destinataireEmail], (err, results) => {
    if (err) return res.status(500).send('Erreur du serveur');
    if (results.length === 0) return res.status(404).send('Destinataire non trouvé.');

    const destinataireId = results[0].id;
    db.query('INSERT INTO messages (expediteur_id, destinataire_id, message) VALUES (?, ?, ?)', [expediteurId, destinataireId, message], (err, result) => {
      if (err) return res.status(500).send('Erreur lors de l\'envoi du message.');
      res.send('Message envoyé avec succès.');
    });
  });
});

app.get('/message', (req, res) => {
  if (!req.session.utilisateurId) {
      return res.status(401).send('Veuillez vous connecter.');
  }
  res.sendFile(path.join(__dirname, 'views', 'message.html'));
});

app.post('/message', (req, res) => {
  const { destinataires, message } = req.body;

  if (!req.session.utilisateurId) {
      return res.status(401).send('Veuillez vous connecter.');
  }

  db.query('INSERT INTO messages (expediteur_id, destinataires, message) VALUES (?, ?, ?)', 
  [req.session.utilisateurId, destinataires, message], (err, result) => {
      if (err) {
          console.error('Erreur lors de l\'envoi du message :', err);
          return res.status(500).send('Erreur lors de l\'envoi du message.');
      }
      res.send('Message envoyé avec succès.');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).send('Erreur lors de la déconnexion.');
    res.send('Déconnexion réussie.');
  });
});

app.listen(port, () => {
  console.log(`Serveur Express en écoute sur http://localhost:${port}`);
});
