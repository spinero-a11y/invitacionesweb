const express = require('express');
const oracledb = require('oracledb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Servir archivos estáticos de la carpeta actual y de la subcarpeta 'invitacionesweb'
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, 'invitacionesweb')));

// Configuración de conexión a tu Oracle FreeSQL (23ai)
const dbConfig = {
  user: "MOON_PEPA2010_SCHEMA_I93AQ",
  password: "TU_CONTRASEÑA_AQUÍ", // ⚠️ Reemplaza por tu contraseña real
  connectString: "tcps://db.freesql.com:2484/23ai_34ui2"
};

const SECRET_KEY = 'clave_secreta_para_tokens';

// --- RUTA 1: REGISTRO DE USUARIOS ---
app.post('/api/registro', async (req, res) => {
  const { nombre, email, password } = req.body;
  let connection;

  try {
    connection = await oracledb.getConnection(dbConfig);

    // Encriptar la contraseña antes de guardarla
    const passwordHash = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO usuarios (nombre, email, password_hash) VALUES (:1, :2, :3)`;
    await connection.execute(sql, [nombre, email, passwordHash], { autoCommit: true });

    res.status(201).json({ mensaje: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ mensaje: 'Error al registrar usuario en la BD', error: error.message });
  } finally {
    if (connection) await connection.close();
  }
});

// --- RUTA 2: INICIO DE SESIÓN ---
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

    // Verificar contraseña encriptada
    const passwordValido = await bcrypt.compare(password, passwordHash);
    if (!passwordValido) {
      return res.status(401).json({ mensaje: 'Correo o contraseña incorrectos' });
    }

    // Crear token de sesión
    const token = jwt.sign({ userId: id, nombre }, SECRET_KEY, { expiresIn: '8h' });

    res.json({ mensaje: 'Login exitoso', token, usuario: { id, nombre } });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ mensaje: 'Error en el servidor', error: error.message });
  } finally {
    if (connection) await connection.close();
  }
});

// Ruta por defecto para servir login.html
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'), (err) => {
    if (err) {
      // Si no está en la raíz, busca dentro de 'invitacionesweb'
      res.sendFile(path.join(__dirname, 'invitacionesweb', 'login.html'));
    }
  });
});

// Encender servidor en el puerto 3000
app.listen(3000, () => {
  console.log('🚀 Servidor corriendo correctamente en http://localhost:3000/login.html');
});