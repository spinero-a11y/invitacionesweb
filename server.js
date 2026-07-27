const express = require('express');
const oracledb = require('oracledb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// Configuración básica
const SECRET_KEY = process.env.JWT_SECRET || 'clave_secreta_para_tokens'; // Idealmente usar variables de entorno
const PORT = process.env.PORT || 3000;

// Configuración de conexión a Oracle FreeSQL (23ai)
const dbConfig = {
  user: "MOON_PEPA2010_SCHEMA_I93AQ",
  password: "TU_CONTRASEÑA_AQUÍ", // ⚠️ Reemplaza por tu contraseña real
  connectString: "tcps://db.freesql.com:2484/23ai_34ui2"
};

// Middleware global
app.use(express.json({ limit: '10mb' }));
app.use(cors());

// Servir archivos estáticos
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, '..')));

// ==========================================
// MIDDLEWARE DE AUTENTICACIÓN (JWT)
// ==========================================
const verificarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expects: "Bearer <TOKEN>"

  if (!token) {
    return res.status(401).json({ mensaje: 'Acceso denegado: Token no proporcionado' });
  }

  try {
    const verificado = jwt.verify(token, SECRET_KEY);
    req.usuario = verificado; // Guardamos la info del token (userId, nombre) en la request
    next();
  } catch (error) {
    return res.status(403).json({ mensaje: 'Token inválido o expirado' });
  }
};

// ==========================================
// RUTAS DE ARCHIVOS HTML
// ==========================================
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'), (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, '..', 'login.html'), (err2) => {
        if (err2) res.status(404).send('No se encontró login.html');
      });
    }
  });
});

app.get('/editor.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'editor.html'), (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, '..', 'editor.html'), (err2) => {
        if (err2) res.status(404).send('No se encontró editor.html');
      });
    }
  });
});

// ==========================================
// RUTAS API
// ==========================================

// 1. REGISTRO
app.post('/api/registro', async (req, res) => {
  const { nombre, email, password } = req.body;
  let connection;

  if (!nombre || !email || !password) {
    return res.status(400).json({ mensaje: 'Todos los campos son obligatorios' });
  }

  try {
    connection = await oracledb.getConnection(dbConfig);
    const passwordHash = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO usuarios (nombre, email, password_hash) VALUES (:1, :2, :3)`;
    await connection.execute(sql, [nombre, email], { autoCommit: true });

    res.status(201).json({ mensaje: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('Error en registro:', error);
    if (error.message && error.message.includes('ORA-00001')) {
      return res.status(400).json({ mensaje: 'El correo electrónico ya está registrado.' });
    }
    res.status(500).json({ mensaje: 'Error al registrar usuario en la BD', error: error.message });
  } finally {
    if (connection) await connection.close();
  }
});

// 2. LOGIN
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  let connection;

  try {
    connection = await oracledb.getConnection(dbConfig);

    const sql = `SELECT id, nombre, password_hash FROM usuarios WHERE email = :1`;
    const result = await connection.execute(sql, [email]);

    if (!result.rows || result.rows.length === 0) {
      return res.status(401).json({ mensaje: 'Correo o contraseña incorrectos' });
    }

    const [id, nombre, passwordHash] = result.rows[0];
    const passwordValido = await bcrypt.compare(password, passwordHash);

    if (!passwordValido) {
      return res.status(401).json({ mensaje: 'Correo o contraseña incorrectos' });
    }

    // Generar Token
    const token = jwt.sign({ userId: id, nombre }, SECRET_KEY, { expiresIn: '8h' });

    res.json({ mensaje: 'Login exitoso', token, usuario: { id, nombre, email } });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ mensaje: 'Error en el servidor', error: error.message });
  } finally {
    if (connection) await connection.close();
  }
});

// 3. CREAR BOCETO (Protegido por Token y Check Admin)
app.post('/api/bocetos', verificarToken, async (req, res) => {
  const { titulo, imagen_preview, contenido_json, es_pro } = req.body;
  const usuarioId = req.usuario.userId; // Obtenido de forma segura desde el JWT
  let connection;

  try {
    connection = await oracledb.getConnection(dbConfig);

    const checkUser = await connection.execute(
      `SELECT es_admin FROM usuarios WHERE id = :1`,
      [usuarioId]
    );

    if (!checkUser.rows || checkUser.rows.length === 0 || checkUser.rows[0][0] !== 1) {
      return res.status(403).json({ mensaje: 'No tienes permisos para publicar bocetos' });
    }

    const sql = `INSERT INTO bocetos (titulo, imagen_preview, contenido_json, es_pro) 
                 VALUES (:1, :2, :3, :4)`;
    await connection.execute(sql, [titulo, imagen_preview, contenido_json, es_pro ? 1 : 0], { autoCommit: true });

    res.status(201).json({ mensaje: 'Boceto publicado con éxito' });
  } catch (error) {
    console.error('Error al publicar boceto:', error);
    res.status(500).json({ mensaje: 'Error al guardar el boceto', error: error.message });
  } finally {
    if (connection) await connection.close();
  }
});

// 4. OBTENER BOCETOS (Público)
app.get('/api/bocetos', async (req, res) => {
  let connection;

  try {
    connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute(
      `SELECT id, titulo, imagen_preview, es_pro FROM bocetos ORDER BY id DESC`
    );

    const bocetos = result.rows.map(row => ({
      id: row[0],
      titulo: row[1],
      imagenPreview: row[2],
      esPro: row[3] === 1
    }));

    res.json(bocetos);
  } catch (error) {
    console.error('Error al obtener bocetos:', error);
    res.status(500).json({ mensaje: 'Error en el servidor', error: error.message });
  } finally {
    if (connection) await connection.close();
  }
});

// 5. GUARDAR PROYECTO (Protegido por Token)
app.post('/api/proyectos', verificarToken, async (req, res) => {
  const { titulo, contenido_json } = req.body;
  const usuarioId = req.usuario.userId; // Extraído del Token autenticado
  let connection;

  try {
    connection = await oracledb.getConnection(dbConfig);

    const sql = `INSERT INTO proyectos (titulo, contenido_json, usuario_id) VALUES (:1, :2, :3)`;
    await connection.execute(sql, [titulo, contenido_json, usuarioId], { autoCommit: true });

    res.status(201).json({ mensaje: 'Proyecto guardado con éxito' });
  } catch (error) {
    console.error('Error al guardar proyecto:', error);
    res.status(500).json({ mensaje: 'Error al guardar el proyecto', error: error.message });
  } finally {
    if (connection) await connection.close();
  }
});

// Arrancar el servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}/login.html`);
  console.log(`🎨 Editor disponible en http://localhost:${PORT}/editor.html`);
});