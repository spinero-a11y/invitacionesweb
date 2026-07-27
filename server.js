const express = require('express');
const oracledb = require('oracledb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// Middleware
app.use(express.json({ limit: '10mb' })); // Permite guardar JSONs/HTMLs grandes de las invitaciones
app.use(cors());

// Servir archivos estáticos desde la carpeta actual y la carpeta padre
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, '..')));

// Ruta por defecto para login.html
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'), (err) => {
    if (err) {
      // Si no está en la misma carpeta, busca un nivel arriba
      res.sendFile(path.join(__dirname, '..', 'login.html'), (err2) => {
        if (err2) {
          res.status(404).send('No se encontró el archivo login.html en el servidor.');
        }
      });
    }
  });
});

// Configuración de conexión a Oracle FreeSQL (23ai)
const dbConfig = {
  user: "MOON_PEPA2010_SCHEMA_I93AQ",
  password: "TU_CONTRASEÑA_AQUÍ", // ⚠️ Reemplaza por tu contraseña real
  connectString: "tcps://db.freesql.com:2484/23ai_34ui2"
};

const SECRET_KEY = 'clave_secreta_para_tokens';

// ==========================================
// RUTA 1: REGISTRO DE USUARIOS
// ==========================================
app.post('/api/registro', async (req, res) => {
  const { nombre, email, password } = req.body;
  let connection;

  try {
    connection = await oracledb.getConnection(dbConfig);

    const passwordHash = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO usuarios (nombre, email, password_hash) VALUES (:1, :2, :3)`;
    await connection.execute(sql, [nombre, email, passwordHash], { autoCommit: true });

    res.status(201).json({ mensaje: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('Error en registro:', error);
    if (error.message.includes('ORA-00001')) {
      return res.status(400).json({ mensaje: 'El correo electrónico ya está registrado.' });
    }
    res.status(500).json({ mensaje: 'Error al registrar usuario en la BD', error: error.message });
  } finally {
    if (connection) await connection.close();
  }
});

// ==========================================
// RUTA 2: INICIO DE SESIÓN
// ==========================================
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

    const token = jwt.sign({ userId: id, nombre }, SECRET_KEY, { expiresIn: '8h' });

    res.json({ mensaje: 'Login exitoso', token, usuario: { id, nombre, email } });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ mensaje: 'Error en el servidor', error: error.message });
  } finally {
    if (connection) await connection.close();
  }
});

// ==========================================
// RUTA 3: CREAR UN BOCETO (Solo Creadora/Admin)
// ==========================================
app.post('/api/bocetos', async (req, res) => {
  const { titulo, imagen_preview, contenido_json, es_pro, usuarioId } = req.body;
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

// ==========================================
// RUTA 4: OBTENER TODOS LOS BOCETOS (Para la galería)
// ==========================================
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

// ==========================================
// RUTA 5: GUARDAR PROYECTO DE USUARIO (NUEVA)
// ==========================================
app.post('/api/proyectos', async (req, res) => {
  const { titulo, contenido_json, usuarioId } = req.body;
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

// ==========================================
// RUTAS DE ARCHIVOS HTML Y ARRANQUE DEL SERVIDOR
// ==========================================
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'), (err) => {
    if (err) res.sendFile(path.join(__dirname, 'invitacionesweb', 'login.html'));
  });
});

app.get('/editor.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'editor.html'), (err) => {
    if (err) res.sendFile(path.join(__dirname, 'invitacionesweb', 'editor.html'));
  });
});

// Escuchar en el puerto 3000
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}/login.html`);
  console.log(`🎨 Editor disponible en http://localhost:${PORT}/editor.html`);
});