import express, { Request, Response, NextFunction } from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import {
  initDb,
  getVulnSettings,
  setVulnSetting,
  findUserByCredentials,
  findUserById,
  getAllUsers,
  getAllComments,
  addComment,
  deleteComment,
  VulnSettings,
} from './db.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

declare module 'express-session' {
  interface SessionData {
    user?: {
      id: number;
      username: string;
      role: 'admin' | 'user';
    };
  }
}

declare global {
  namespace Express {
    interface Request {
      vulnSettings?: VulnSettings;
    }
  }
}

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.set('trust proxy', 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'tajni_kljuc_za_web2_projekt2',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
    },
  })
);

async function loadVulnSettings(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const settings = await getVulnSettings();
    req.vulnSettings = settings;

    const cookiePayload = req.session.user
      ? `user=${req.session.user.username}|role=${req.session.user.role}|session=active`
      : 'guest=anon|session=active';

    res.cookie('session_info', cookiePayload, {
      httpOnly: !settings.xss,
      sameSite: 'lax',
    });

    next();
  } catch (err) {
    next(err);
  }
}

app.use(loadVulnSettings);

app.get('/', async (req: Request, res: Response) => {
  const comments = await getAllComments();
  res.render('index', {
    user: req.session.user ?? null,
    settings: req.vulnSettings ?? { xss: true, bac: true },
    comments,
    profileResult: null,
    adminUsers: null,
    message: typeof req.query.msg === 'string' ? req.query.msg : null,
    error: typeof req.query.err === 'string' ? req.query.err : null,
  });
});

app.post('/login', async (req: Request, res: Response) => {
  const username = String(req.body.username ?? '').trim();
  const password = String(req.body.password ?? '').trim();

  const user = await findUserByCredentials(username, password);
  if (!user) {
    res.redirect('/?err=' + encodeURIComponent('Neispravno korisničko ime ili lozinka.'));
    return;
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
  };

  res.redirect('/?msg=' + encodeURIComponent(`Uspješna prijava kao ${user.username} (${user.role}).`));
});

app.post('/logout', (req: Request, res: Response) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.clearCookie('session_info');
    res.redirect('/?msg=' + encodeURIComponent('Uspješno ste odjavljeni.'));
  });
});

app.post('/toggle', async (req: Request, res: Response) => {
  const vulnType = req.body.vulnType; // 'xss' ili 'bac'
  const enabled = req.body.enabled === 'true';

  if (vulnType === 'xss' || vulnType === 'bac') {
    await setVulnSetting(vulnType, enabled);
  }
  res.redirect('/?msg=' + encodeURIComponent(`Postavka ranjivosti (${vulnType}) ažurirana.`));
});

app.post('/comment', async (req: Request, res: Response) => {
  const content = String(req.body.content || '');
  const author = req.session.user ? req.session.user.username : 'Gost';

  await addComment(author, content);
  res.redirect('/?msg=' + encodeURIComponent('Komentar dodan na oglasnu ploču.'));
});

app.post('/comment/delete/:id', async (req: Request, res: Response) => {
  const id = parseInt(String(req.params.id), 10);
  if (!isNaN(id)) {
    await deleteComment(id);
  }
  res.redirect('/?msg=' + encodeURIComponent('Komentar obrisan.'));
});

app.get('/profile', async (req: Request, res: Response) => {
  const userId = parseInt(req.query.userId as string, 10);
  if (isNaN(userId)) {
    res.redirect('/?err=' + encodeURIComponent('Nevažeći ID korisnika.'));
    return;
  }

  const settings = req.vulnSettings;
  const currentUser = req.session.user;

  if (!settings?.bac) {
    if (!currentUser) {
      res.status(401).send('401 Unauthorized - Morate biti prijavljeni za pristup profilu.');
      return;
    }
    if (currentUser.id !== userId && currentUser.role !== 'admin') {
      res.status(403).send('403 Forbidden - Nemate ovlasti za pregled tuđeg privatnog profila (IDOR zaštićen).');
      return;
    }
  }

  const targetUser = await findUserById(userId);
  if (!targetUser) {
    res.redirect('/?err=' + encodeURIComponent('Traženi korisnik nije pronađen.'));
    return;
  }

  const comments = await getAllComments();
  res.render('index', {
    user: currentUser ?? null,
    settings: settings ?? { xss: true, bac: true },
    comments,
    profileResult: targetUser,
    adminUsers: null,
    message: null,
    error: null,
  });
});

// Administratorski prikaz korisnika (Ranjivost 2: Neovlašteni pristup ruti)
app.get('/admin/users', async (req: Request, res: Response) => {
  const settings = req.vulnSettings;
  const currentUser = req.session.user;

  if (!settings?.bac) {
    if (!currentUser) {
      res.status(401).send('401 Unauthorized - Morate biti prijavljeni.');
      return;
    }
    if (currentUser.role !== 'admin') {
      res.status(403).send('403 Forbidden - Samo administratori imaju pristup ovoj ruti.');
      return;
    }
  }

  const allUsers = await getAllUsers();
  const comments = await getAllComments();

  res.render('index', {
    user: currentUser ?? null,
    settings: settings ?? { xss: true, bac: true },
    comments,
    profileResult: null,
    adminUsers: allUsers, 
    message: null,
    error: null,
  });
});

const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const host = process.env.RENDER_EXTERNAL_URL ? '0.0.0.0' : 'localhost';

initDb()
  .then(() => {
    app.listen(port, host, () => {
      console.log(`Poslužitelj je pokrenut na http://${host}:${port}`);
      if (process.env.RENDER_EXTERNAL_URL) {
        console.log(`Render vanjski URL: ${process.env.RENDER_EXTERNAL_URL}`);
      }
    });
  })
  .catch((err) => {
    console.error('Greška pri inicijalizaciji baze podataka:', err);
    process.exit(1);
  });