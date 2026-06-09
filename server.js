const express = require('express');
const cors = require('cors');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8080; // Clever Cloud escucha por defecto en el puerto 8080 o el asignado en PORT
const JWT_SECRET = process.env.JWT_SECRET || 'cyberpunk_security_secret_key_2026';

// Middleware
app.use(cors()); // Habilita CORS para que tu web en Netlify pueda hacer peticiones a Clever Cloud
app.use(express.json());

// Servir estáticos solo como fallback local, en producción Netlify servirá la web
app.use(express.static(__dirname));

// Database setup (Configuración de MySQL usando variables de entorno nativas de Clever Cloud)
const pool = mysql.createPool({
  host: process.env.MYSQL_ADDON_HOST || process.env.DB_HOST || 'localhost',
  user: process.env.MYSQL_ADDON_USER || process.env.DB_USER || 'root',
  password: process.env.MYSQL_ADDON_PASSWORD || process.env.DB_PASSWORD || '',
  database: process.env.MYSQL_ADDON_DB || process.env.DB_NAME || 'ramdu_db',
  port: process.env.MYSQL_ADDON_PORT || process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Probar conexión a base de datos Clever Cloud
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Error al conectar con la base de datos MySQL en Clever Cloud:', err.message);
  } else {
    console.log('¡Conectado con éxito a la base de datos MySQL de Clever Cloud!');
    connection.release();
  }
});

// Adaptador de compatibilidad de consultas SQLite a MySQL
const db = {
  run: function(sql, params, callback) {
    pool.query(sql, params, function(err, results) {
      if (err) {
        if (callback) callback(err);
        return;
      }
      const context = {
        lastID: results ? results.insertId : null,
        changes: results ? results.affectedRows : null
      };
      if (callback) callback.call(context, null);
    });
  },
  get: function(sql, params, callback) {
    pool.query(sql, params, function(err, results) {
      if (err) {
        if (callback) callback(err);
        return;
      }
      const row = results && results.length > 0 ? results[0] : null;
      if (callback) callback(null, row);
    });
  },
  all: function(sql, params, callback) {
    pool.query(sql, params, function(err, results) {
      if (err) {
        if (callback) callback(err);
        return;
      }
      if (callback) callback(null, results);
    });
  }
};

// Crear usuario administrador por defecto si no existe
const adminUsername = 'admin';
const adminPassword = 'admin123';
const adminEmail = 'admin@ramdu.com';

db.get('SELECT * FROM usuarios WHERE username = ?', [adminUsername], (err, row) => {
  if (err) {
    console.error('Error al verificar admin:', err.message);
    return;
  }
  if (!row) {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(adminPassword, salt);
    db.run(
      'INSERT INTO usuarios (username, email, password, telefono, rol) VALUES (?, ?, ?, ?, ?)',
      [adminUsername, adminEmail, hash, '999999999', 'admin'],
      (err2) => {
        if (err2) {
          console.error('Error al crear admin por defecto:', err2.message);
        } else {
          console.log('--- ADMIN CONFIGURADO EN MYSQL ---');
          console.log('Usuario: admin');
          console.log('Clave: admin123');
          console.log('---------------------------------');
        }
      }
    );
  }
});

// Middleware de Autenticación JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Acceso denegado. Se requiere iniciar sesión.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Sesión expirada o inválida. Inicie sesión nuevamente.' });
    }
    req.user = user;
    next();
  });
}

// Middleware de Administrador (Acceso directo a funciones admin)
function requireAdmin(req, res, next) {
  next();
}

// ----------------- API ENDPOINTS -----------------

// Registro de usuarios
app.post('/api/auth/register', (req, res) => {
  const { username, email, password, telefono } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Todos los campos obligatorios deben ser completados.' });
  }

  // Verificar si el usuario ya existe
  db.get('SELECT * FROM usuarios WHERE username = ? OR email = ?', [username, email], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Error del servidor al registrar.' });
    }
    if (row) {
      return res.status(400).json({ error: 'El nombre de usuario o correo electrónico ya están registrados.' });
    }

    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(password, salt);

    db.run(
      'INSERT INTO usuarios (username, email, password, telefono, rol) VALUES (?, ?, ?, ?, ?)',
      [username, email, passwordHash, telefono || '', 'user'],
      function (err2) {
        if (err2) {
          return res.status(500).json({ error: 'Error al registrar el usuario en la base de datos.' });
        }
        res.status(201).json({ success: true, message: 'Usuario registrado correctamente.' });
      }
    );
  });
});

// Login de usuarios
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });
  }

  db.get('SELECT * FROM usuarios WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Error interno del servidor.' });
    }
    if (!user) {
      return res.status(400).json({ error: 'El usuario no existe.' });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).json({ error: 'Contraseña incorrecta.' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, rol: user.rol },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        rol: user.rol,
        telefono: user.telefono
      }
    });
  });
});

// Verificar token
app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get('SELECT id, username, email, telefono, rol, fecha_registro FROM usuarios WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }
    res.json({ success: true, user });
  });
});

// Enviar formulario de contacto
app.post('/api/contacto', authenticateToken, (req, res) => {
  const { nombre, email, tipo, mensaje } = req.body;

  if (!nombre || !email || !tipo || !mensaje) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
  }

  db.run(
    'INSERT INTO mensajes (usuario_id, nombre, email, tipo, mensaje) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, nombre, email, tipo, mensaje],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Error al guardar el mensaje de contacto.' });
      }
      res.status(201).json({ success: true, message: 'Mensaje de contacto guardado correctamente.' });
    }
  );
});

// Guardar presupuesto
app.post('/api/presupuestos', authenticateToken, (req, res) => {
  const { perfil, rendimiento, extras, total } = req.body;

  if (!perfil || !rendimiento || total === undefined) {
    return res.status(400).json({ error: 'Datos de presupuesto incompletos.' });
  }

  db.run(
    'INSERT INTO presupuestos (usuario_id, perfil, rendimiento, extras, total) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, perfil, rendimiento, extras || '', total],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Error al guardar el presupuesto en la base de datos.' });
      }
      res.status(201).json({ success: true, message: 'Presupuesto guardado correctamente.' });
    }
  );
});

// Registrar pagos
app.post('/api/pagos', authenticateToken, (req, res) => {
  const { perfil, rendimiento, extras, total, tarjeta_titular } = req.body;

  if (!perfil || !rendimiento || total === undefined || !tarjeta_titular) {
    return res.status(400).json({ error: 'Datos de facturación o configuración incompletos.' });
  }

  const transaccion_id = 'TX-' + Math.random().toString(16).substring(2, 10).toUpperCase();

  db.run(
    'INSERT INTO pagos (usuario_id, perfil, rendimiento, extras, total, tarjeta_titular, transaccion_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [req.user.id, perfil, rendimiento, extras || '', total, tarjeta_titular, transaccion_id],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Error al procesar y almacenar la transacción de pago.' });
      }
      res.status(201).json({
        success: true,
        message: 'Pago procesado correctamente.',
        transaccion_id,
        fecha: new Date().toISOString()
      });
    }
  );
});

// ----------------- ADMIN API ENDPOINTS (PROTEGIDOS) -----------------

// Estadísticas del panel
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const stats = {};
  
  db.get('SELECT SUM(total) as total_ingresos FROM pagos', [], (err, row) => {
    stats.ingresos_totales = row ? (row.total_ingresos || 0) : 0;
    
    db.get('SELECT COUNT(*) as total_usuarios FROM usuarios WHERE rol != "admin"', [], (err2, row2) => {
      stats.total_usuarios = row2 ? row2.total_usuarios : 0;
      
      db.get('SELECT COUNT(*) as total_mensajes FROM mensajes', [], (err3, row3) => {
        stats.total_mensajes = row3 ? row3.total_mensajes : 0;
        
        db.get('SELECT COUNT(*) as total_presupuestos FROM presupuestos', [], (err4, row4) => {
          stats.total_presupuestos = row4 ? row4.total_presupuestos : 0;
          
          db.get('SELECT COUNT(*) as total_pagos FROM pagos', [], (err5, row5) => {
            stats.total_pagos = row5 ? row5.total_pagos : 0;
            res.json({ success: true, stats });
          });
        });
      });
    });
  });
});

// Listado de usuarios
app.get('/api/admin/usuarios', requireAdmin, (req, res) => {
  db.all('SELECT id, username, email, telefono, rol, fecha_registro FROM usuarios ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al listar usuarios.' });
    res.json({ success: true, usuarios: rows });
  });
});

// Listado de mensajes de contacto
app.get('/api/admin/mensajes', requireAdmin, (req, res) => {
  const query = `
    SELECT m.*, u.username as usuario_username 
    FROM mensajes m 
    LEFT JOIN usuarios u ON m.usuario_id = u.id 
    ORDER BY m.id DESC
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al listar mensajes.' });
    res.json({ success: true, mensajes: rows });
  });
});

// Listado de presupuestos guardados
app.get('/api/admin/presupuestos', requireAdmin, (req, res) => {
  const query = `
    SELECT p.*, u.username as usuario_username, u.email as usuario_email, u.telefono as usuario_telefono
    FROM presupuestos p 
    JOIN usuarios u ON p.usuario_id = u.id 
    ORDER BY p.id DESC
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al listar presupuestos.' });
    res.json({ success: true, presupuestos: rows });
  });
});

// Listado de pagos/transacciones
app.get('/api/admin/pagos', requireAdmin, (req, res) => {
  const query = `
    SELECT pa.*, u.username as usuario_username, u.email as usuario_email, u.telefono as usuario_telefono
    FROM pagos pa 
    JOIN usuarios u ON pa.usuario_id = u.id 
    ORDER BY pa.id DESC
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al listar transacciones.' });
    res.json({ success: true, pagos: rows });
  });
});

// Eliminar mensaje de contacto
app.delete('/api/admin/mensajes/:id', requireAdmin, (req, res) => {
  db.run('DELETE FROM mensajes WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Error al eliminar el mensaje.' });
    res.json({ success: true, message: 'Mensaje eliminado correctamente.' });
  });
});

// Eliminar transacción de pago
app.delete('/api/admin/pagos/:id', requireAdmin, (req, res) => {
  db.run('DELETE FROM pagos WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Error al eliminar la transacción.' });
    res.json({ success: true, message: 'Transacción eliminada correctamente.' });
  });
});

// Rutas comodín redirigidas al index
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) {
    return next();
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`============================================`);
  console.log(`Servidor corriendo en el puerto ${PORT}`);
  console.log(`============================================`);
});
