// Dépendances
require('dotenv').config();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const mysql = require('mysql2');
const { Strategy: DiscordStrategy } = require('passport-discord');
const path = require('path');
const axios = require('axios');
const multer = require('multer');
const fs = require('fs');

// Initialisation de l'application Express
const app = express();
const port = 3000;

// Définir EJS comme moteur de vues
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware pour fichiers statiques
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Configuration de multer pour les uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/galerie/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const extension = file.originalname.split('.').pop();
    cb(null, `${file.fieldname}-${uniqueSuffix}.${extension}`);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: function (req, file, cb) {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'video/mp4', 'video/webm'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Format non supporté'));
    }
  }
});

// Configuration MySQL
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'Chausette-11',
  database: 'whitelist_fivem'
};
const connection = mysql.createConnection(dbConfig);
connection.connect(err => {
  if (err) {
    console.error("Erreur de connexion à MySQL:", err);
    return;
  }
  console.log("Connecté à MySQL");
});

// Session
const sessionStore = new MySQLStore({}, connection);
app.use(session({
  secret: 'tonSecretDeSession',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 86400000 }
}));

// Auth Discord
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL,
  scope: ['identify', 'guilds', 'guilds.members.read']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Appel API Discord pour récupérer les rôles du user dans le serveur
    const response = await axios.get(`https://discord.com/api/v10/users/@me/guilds/${process.env.DISCORD_GUILD_ID}/member`, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    const member = response.data;
    const hasStaffRole = member.roles.includes(process.env.DISCORD_STAFF_ROLE_ID);

    profile.isModerator = hasStaffRole; // ✅ Ajoute la propriété à l'utilisateur
    return done(null, profile);
  } catch (err) {
    console.error("Erreur lors de la récupération du membre Discord :", err);
    return done(err, profile);
  }
}));


passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => {
  done(null, user);
});


app.use(passport.initialize());
app.use(passport.session());

// Middleware global pour rendre user, isAuthenticated et isModerator dispo dans toutes les vues EJS
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.isAuthenticated = req.isAuthenticated();
  res.locals.isModerator = req.user?.isModerator || false;
  next();
});


// Middlewares
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  req.session.redirectAfterLogin = req.originalUrl;
  res.redirect('/auth/discord');
}

function isStaff(req, res, next) {
  if (req.isAuthenticated()) {
    const userGuilds = req.user.guilds || [];
    const staffRole = 'Staff';
    let hasStaffRole = false;

    for (let guild of userGuilds) {
      if (guild.roles && Array.isArray(guild.roles)) {
        hasStaffRole = guild.roles.includes(staffRole);
      }
      if (hasStaffRole) break;
    }

    return hasStaffRole ? next() : res.redirect('/');
  }
  res.redirect('/auth/discord');
}

// Routes
app.get('/', (req, res) => res.redirect('/accueil'));

app.get('/accueil', (req, res) => {
  res.render('accueil', {
    isAuthenticated: req.isAuthenticated(),
    user: req.user,
    currentPage: 'accueil',
    isModerator: req.user?.isModerator || false
  });
});

app.get('/auth/discord', (req, res, next) => {
  passport.authenticate('discord')(req, res, next);
});

app.get('/auth/discord/callback', passport.authenticate('discord', {
  failureRedirect: '/login'
}), (req, res) => {
  const redirectURL = req.session.redirectAfterLogin || '/';
  delete req.session.redirectAfterLogin;
  res.redirect(redirectURL);
});

app.get('/candidature', isLoggedIn, (req, res) => {
  const discordId = req.user.id;

  const query = 'SELECT * FROM candidatures WHERE discordId = ? AND statut != "finale"';
  connection.query(query, [discordId], (err, results) => {
    if (err) {
      console.error("Erreur vérification candidature existante:", err);
      return res.send("Erreur serveur");
    }

    const candidatureExistante = results.length > 0;

    res.render('candidature', {
      user: req.user,
      candidatureExistante,
      candidature: results[0] || null,
      isAuthenticated: req.isAuthenticated(),
      isModerator: req.user?.isModerator || false,
      currentPage: 'candidature'
    });
  });
});


app.post('/candidature', (req, res) => {
  const discordId = req.user.id;

  const checkQuery = 'SELECT * FROM candidatures WHERE discordId = ? AND statut != "finale"';
  connection.query(checkQuery, [discordId], (err, results) => {
    if (err) {
      console.error("Erreur vérification doublon:", err);
      return res.send("Erreur serveur.");
    }

    if (results.length > 0) {
      return res.send("Vous avez déjà une candidature en cours. Merci de patienter.");
    }

    // Sinon, insertion normale
    const { pseudo, birthdate, experience, personnage, typePersonnage, background, motivation } = req.body;
    const insertQuery = 'INSERT INTO candidatures (pseudo, discordId, birthdate, experience, personnage, typePersonnage, background, motivation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    connection.query(insertQuery, [pseudo, discordId, birthdate, experience, personnage, typePersonnage, background, motivation], (err) => {
      if (err) {
        console.error("Erreur insertion candidature:", err);
        return res.send('Erreur lors de la soumission');
      }
      res.render('confirmation', { user: req.user });
    });
  });
});


app.get('/login', (req, res) => {
  res.send(`
    <h1>Login Modérateur</h1>
    <form action="/login" method="POST">
      <label for="username">Nom d'utilisateur:</label>
      <input type="text" id="username" name="username" required><br><br>
      <label for="password">Mot de passe:</label>
      <input type="password" id="password" name="password" required><br><br>
      <input type="submit" value="Se connecter">
    </form>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === process.env.MODERATOR_USERNAME && password === process.env.MODERATOR_PASSWORD) {
    req.session.isModerator = true;
    res.redirect('/moderators'); // ❌ ancienne route
  } else {
    res.send('Identifiants incorrects');
  }
});


app.get('/moderators', isLoggedIn, (req, res) => {
  if (req.session.isModerator) {
    const query = 'SELECT * FROM candidatures';
    connection.query(query, (err, results) => {
      if (err) {
        console.error("Erreur récupération candidatures:", err);
        return res.send("Erreur de récupération");
      }
      res.render('moderators', {
        user: req.user,
        isModerator: true,
        applications: results
      });
    });
  } else {
    res.send('<h1>Accès refusé</h1><p>Réservé aux modérateurs.</p>');
  }
});

const DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/TON_WEBHOOK_ID/TON_TOKEN';

app.post('/moderators/treatment', isLoggedIn, (req, res) => {
  if (!req.user || !req.user.isModerator) {
    return res.status(403).render('access-denied');
  }

  const { id, action, note } = req.body;

  const query = 'SELECT * FROM candidatures WHERE id = ?';
  connection.query(query, [id], (err, results) => {
    if (err || results.length === 0) {
      console.error("Erreur récupération candidature:", err);
      return res.send("Candidature introuvable.");
    }

    const candidature = results[0];

    const color = action === 'accepter' ? 0x28a745 : 0xdc3545;
    const emoji = action === 'accepter' ? '✅' : '❌';

    const embed = {
      title: `${emoji} Candidature ${action === 'accepter' ? 'ACCEPTÉE' : 'REFUSÉE'}`,
      color: color,
      fields: [
        { name: "Pseudo Discord", value: candidature.pseudo, inline: true },
        { name: "ID Discord", value: candidature.discordId, inline: true },
        { name: "Nom RP", value: candidature.personnage, inline: true },
        { name: "Type", value: candidature.typePersonnage, inline: true },
        { name: "Date de naissance", value: candidature.birthdate, inline: true },
        { name: "Motivation", value: candidature.motivation || "Aucune" }
      ],
      timestamp: new Date().toISOString(),
      footer: { text: "Pantheon RP - Modération" }
    };

    if (candidature.statut === 'entretien') {
      // Passage en "finale" avec note
      const finalQuery = 'UPDATE candidatures SET statut = "finale", note = ? WHERE id = ?';
      connection.query(finalQuery, [parseInt(note), id], async (err) => {
        if (err) {
          console.error("Erreur traitement finale:", err);
          return res.send("Erreur traitement.");
        }

        try {
          await axios.post(DISCORD_WEBHOOK_URL, {
            content: `<@${candidature.discordId}>`,
            embeds: [embed]
          });
        } catch (error) {
          console.error("Erreur envoi webhook:", error);
        }

        return res.redirect('/espace-staff');
      });
    } else {
      // Cas de la première étape : accepter = passage en entretien / refuser = suppression
      if (action === 'accepter') {
        const updateQuery = 'UPDATE candidatures SET statut = "entretien" WHERE id = ?';
        connection.query(updateQuery, [id], async (err) => {
          if (err) {
            console.error("Erreur mise à jour statut:", err);
            return res.send("Erreur lors du traitement.");
          }

          try {
            await axios.post(DISCORD_WEBHOOK_URL, {
              content: `<@${candidature.discordId}>`,
              embeds: [embed]
            });
          } catch (error) {
            console.error("Erreur webhook:", error);
          }

          return res.redirect('/espace-staff');
        });
      } else if (action === 'refuser') {
        const deleteQuery = 'DELETE FROM candidatures WHERE id = ?';
        connection.query(deleteQuery, [id], async (err) => {
          if (err) {
            console.error("Erreur suppression:", err);
            return res.send("Erreur traitement.");
          }

          try {
            await axios.post(DISCORD_WEBHOOK_URL, {
              content: `<@${candidature.discordId}>`,
              embeds: [embed]
            });
          } catch (error) {
            console.error("Erreur webhook:", error);
          }

          return res.redirect('/espace-staff');
        });
      } else {
        return res.status(400).send("Action inconnue.");
      }
    }
  });
});

app.post('/moderators/delete', isLoggedIn, (req, res) => {
  if (!req.user || !req.user.isModerator) {
    return res.status(403).json({ message: 'Accès refusé' });
  }

  const { id } = req.body;

  if (!id) {
    return res.status(400).json({ message: 'ID manquant' });
  }

  const deleteQuery = 'DELETE FROM candidatures WHERE id = ?';
  connection.query(deleteQuery, [id], (err) => {
    if (err) {
      console.error("Erreur suppression candidature WL finale:", err);
      return res.status(500).json({ message: 'Erreur lors de la suppression' });
    }

    // Réponse simple pour confirmer au JS que la suppression est ok
    res.sendStatus(200);
  });
});


app.get('/espace-staff', (req, res) => {
  if (!req.isAuthenticated()) {
    req.session.redirectAfterLogin = '/espace-staff';
    return res.redirect('/auth/discord');
  }

  // Si l'utilisateur est connecté mais n'est pas modérateur
  if (!req.user?.isModerator) {
    return res.status(403).render('access-denied', {
      user: req.user,
      isAuthenticated: req.isAuthenticated(),
      isModerator: false // important !
    });
  }

  // Si c’est un modérateur → affichage normal
  const query = 'SELECT * FROM candidatures ORDER BY id DESC';
  connection.query(query, (err, results) => {
    if (err) {
      console.error("Erreur récupération candidatures:", err);
      return res.send("Erreur lors de la récupération des candidatures.");
    }

    res.render('espace-staff', {
      user: req.user,
      isAuthenticated: true,
      isModerator: true,
      currentPage: 'espace-staff',
      applications: results
    });
  });
});


app.get('/qui-sommes-nous', (req, res) => {
  res.render('qui-sommes-nous', {
    user: req.user,
    isModerator: req.session.isModerator,
    currentPage: 'qui-sommes-nous'
  });
});

app.get('/comment-nous-rejoindre', (req, res) => {
  res.render('comment-nous-rejoindre', {
    user: req.user,
    isModerator: req.session.isModerator,
    currentPage: 'comment-nous-rejoindre'
  });
});

app.get('/galerie', (req, res) => {
  const query = 'SELECT * FROM medias ORDER BY created_at DESC';

  connection.query(query, (err, results) => {
    if (err) {
      console.error("Erreur récupération médias galerie:", err);
      return res.send("Erreur galerie.");
    }

    const isAuthenticated = req.isAuthenticated && req.isAuthenticated();
    const isModerator = req.user?.isModerator === true; // ✅ ici la vraie vérification

    res.render('galerie', {
      user: req.user,
      isAuthenticated,
      isModerator, // ✅ bien passé ici
      currentPage: 'galerie',
      medias: results
    });
  });
});


// Page admin de gestion de la galerie
app.get('/admin/galerie', isLoggedIn, (req, res) => {
  // Vérifie si l'utilisateur est bien modérateur
  if (!req.user || !req.user.isModerator) {
    return res.status(403).render('access_denied', {
      message: "Accès réservé aux modérateurs."
    });
  }

  const query = 'SELECT * FROM medias ORDER BY created_at DESC';
  connection.query(query, (err, results) => {
    if (err) {
      console.error("Erreur récupération médias:", err);
      return res.send("Erreur lors de la récupération des fichiers.");
    }

    res.render('admin-galerie', {
      user: req.user,
      isModerator: true,
      medias: results
    });
  });
});

app.post('/admin/galerie/upload', isLoggedIn, upload.single('file'), (req, res) => {
  if (!req.user || !req.user.isModerator) {
    return res.status(403).send("Accès refusé.");
  }

  const { type } = req.body;
  const file = req.file;

  if (!file || !type) {
    return res.send("Fichier ou type manquant.");
  }

  const query = 'INSERT INTO medias (filename, type) VALUES (?, ?)';
  connection.query(query, [file.filename, type], (err) => {
    if (err) {
      console.error("Erreur enregistrement fichier:", err);
      return res.send("Erreur lors de l’enregistrement du fichier.");
    }

    res.redirect('/admin/galerie');
  });
});


app.post('/admin/galerie/delete', isLoggedIn, (req, res) => {
  if (!req.session.isModerator) return res.send('Accès refusé');

  const { id, filename } = req.body;
  const filePath = path.join(__dirname, 'public', 'uploads', 'galerie', filename);

  // Supprimer le fichier du disque
  fs.unlink(filePath, (err) => {
    if (err) console.error("Erreur suppression fichier:", err);

    const deleteQuery = 'DELETE FROM medias WHERE id = ?';
    connection.query(deleteQuery, [id], (err) => {
      if (err) {
        console.error("Erreur suppression BDD:", err);
        return res.send("Erreur lors de la suppression.");
      }

      res.redirect('/admin/galerie');
    });
  });
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.send("Erreur lors de la déconnexion.");

    // Supprimer la session modérateur si elle existe
    req.session.isModerator = false;

    // Détruire la session complète pour tout vider
    req.session.destroy((err) => {
      if (err) {
        console.error("Erreur lors de la destruction de session :", err);
        return res.send("Erreur de session.");
      }

      res.redirect('/');
    });
  });
});


// Lancement du serveur
app.listen(port, () => {
  console.log(`Serveur lancé sur http://localhost:${port}`);
});
