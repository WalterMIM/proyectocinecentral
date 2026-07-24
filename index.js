const express = require('express');
const path = require('path');
const session = require('express-session'); // Para las sesiones
const conexion = require('./conexion'); // Importa tu archivo de conexión
const app = express();
const bcrypt = require('bcryptjs');
const multer = require('multer'); // Gestor de subida de archivos
const QRCode = require('qrcode');

// ⚙️ CONSTANTE OPERACIONAL DEL MOTOR DE HORARIOS
// Define el tiempo de holgura obligatorio entre funciones para la limpieza de la sala
const MINUTOS_LIMPIEZA = 20; 

// 🔒 MIDDLEWARE DE SEGURIDAD CORREGIDO
// Bloquea o permite el paso a rutas administrativas validando el rol en la sesión activa
function verificarAdmin(req, res, next) {
    if (req.session && req.session.rol === 'admin') {
        return next(); // ¡Autorizado! Continúa
    } else {
        return res.status(403).send(`
            <div style="text-align:center; font-family:sans-serif; margin-top:50px; background:#141414; color:white; padding:30px;">
                <h1 style="color:#e50914;">🚫 Acceso Denegado</h1>
                <p>No tienes permisos de administrador para ver o modificar este panel.</p>
                <a href="/login" style="color:#4CAF50; font-weight:bold; text-decoration:none;">Iniciar Sesión como Admin</a>
            </div>
        `);
    }
}

// ⚙️ CONFIGURACIÓN DE ALMACENAMIENTO DE PORTADAS (MULTER)
// Define la carpeta de destino y renombra los archivos subidos para evitar duplicados usando timestamps
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'public')); 
    },
    filename: (req, file, cb) => {
        const extension = path.extname(file.originalname);
        cb(null, 'portada-' + Date.now() + extension); 
    }
});
const upload = multer({ storage: storage });

// 1. CONFIGURACIONES GENERALES DE EXPRESS
// Middleware para servir archivos estáticos y procesar datos entrantes en formato URL-encoded y JSON
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuración de la sesión en memoria para persistencia local de usuarios
app.use(session({
    secret: 'ClaveSecretaDelCineCentral',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } 
}));

// 2. RUTAS DE NAVEGACIÓN VISUAL (GET CLEAN URLS)
// Despacho de archivos HTML estáticos para la interfaz de usuario
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'Register.html'));
});

app.get('/admin', verificarAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/cartelera', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'Cartelera.html'));
});

app.get('/proximos-estrenos', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'ProximosEstrenos.html'));
});

app.get('/carameleria', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'carameleria.html'));
});

app.get('/contacto', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'Contacto.html'));
});

// Ruta explícita para la vista "Mis Compras" guardada en la carpeta views
app.get('/mis-compras.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'mis-compras.html'));
});

app.get('/recuperar-contrasena', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'recuperar.html'));
});


// 3. RUTAS DE AUTENTICACIÓN (POST)

// LOGUEAR USUARIO
// LOGUEAR USUARIO CORREGIDO
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // 1. Buscamos al usuario SOLO por el email. 
    // Asegúrate de traer la columna 'password' en el SELECT.
    const query = 'SELECT id, nombre, email, password, rol FROM usuarios WHERE email = ?';
    
    conexion.query(query, [email], async (err, results) => {
        if (err) {
            console.error("Error en base de datos:", err);
            return res.status(500).send('Error interno en el servidor');
        }

        // Si el usuario existe (el correo es correcto)
        if (results.length > 0) {
            const usuario = results[0];

            try {
                // 2. Comparamos la contraseña plana ingresada con el hash de la BD
                const contrasenaValida = await bcrypt.compare(password, usuario.password);

                if (contrasenaValida) {
                    // ¡Todo correcto! Iniciamos la sesión
                    req.session.usuarioId = usuario.id;
                    req.session.nombre = usuario.nombre;
                    req.session.rol = usuario.rol;

                    res.redirect('/'); 
                } else {
                    // La contraseña no coincide
                    res.send('<h3>Correo o contraseña incorrectos.</h3><a href="/login">Volver a intentar</a>');
                }
            } catch (compareError) {
                console.error("Error al comparar contraseñas:", compareError);
                return res.status(500).send('Error interno de seguridad.');
            }

        } else {
            // El correo no existe en la BD
            res.send('<h3>Correo o contraseña incorrectos.</h3><a href="/login">Volver a intentar</a>');
        }
    });
});

// REGISTRAR USUARIO
app.post('/register', async (req, res) => {
    const { nombre, email, password } = req.body;

    try {
        const queryCheck = 'SELECT id FROM usuarios WHERE email = ?';
        conexion.query(queryCheck, [email], async (err, results) => {
            if (err) {
                console.error("❌ Error en base de datos al verificar:", err);
                return res.status(500).send('Error al procesar el registro');
            }

            if (results.length > 0) {
                return res.send('<h3>El correo electrónico ya está registrado.</h3><a href="/register">Volver a intentar</a>');
            }

            try {
                const salt = await bcrypt.genSalt(10);
                const passwordHash = await bcrypt.hash(password, salt);

                const queryInsert = 'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)';
                
                conexion.query(queryInsert, [nombre, email, passwordHash, 'cliente'], (errInsert, result) => {
                    if (errInsert) {
                        console.error("❌ Error al guardar usuario:", errInsert);
                        return res.status(500).send('Error al guardar el usuario.');
                    }
                    
                    req.session.usuarioId = result.insertId;
                    req.session.nombre = nombre;
                    req.session.rol = 'cliente';

                    res.redirect('/'); 
                });
            } catch (hashError) {
                console.error("❌ Error al encriptar contraseña:", hashError);
                return res.status(500).send('Error interno de seguridad.');
            }
        });
    } catch (error) {
        res.status(500).send('Hubo un error al procesar tu registro.');
    }
});


// 4. MÓDULO DE ADMINISTRACIÓN

app.post('/api/admin/agregar-pelicula', verificarAdmin, upload.single('portada'), (req, res) => {
    if (!req.file) return res.status(400).send('Debes seleccionar una imagen.');

    const { titulo, duracion, genero, sala_id, sinopsis, estado } = req.body;
    const portadaURL = '/' + req.file.filename; 
    const minutosDuracion = parseInt(duracion);

    const queryPelicula = 'INSERT INTO peliculas (titulo, duracion, genero, portada, sinopsis, estado) VALUES (?, ?, ?, ?, ?, ?)';
    conexion.query(queryPelicula, [titulo, minutosDuracion, genero, portadaURL, sinopsis, estado || 'cartelera'], (err, resultPelicula) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error al guardar la película');
        }

        if (estado === 'estreno') {
            return res.send(`
                <div style="text-align: center; font-family: sans-serif; margin-top: 50px; color: white; background: #141414; padding: 20px;">
                    <h1 style="color: #4CAF50;">¡Próximo Estreno Guardado! 🚀</h1>
                    <p>La película <strong>${titulo}</strong> se guardó exitosamente.</p>
                    <a href="/admin" style="color: #e50914; font-weight: bold; text-decoration: none;">Volver al Panel</a>
                </div>
            `);
        }

        const peliculaId = resultPelicula.insertId;

        const querySala = 'SELECT hora_apertura, hora_cierre FROM salas WHERE id = ?';
        conexion.query(querySala, [sala_id], (err, salas) => {
            if (err || salas.length === 0) {
                return res.status(500).send('Error al obtener los datos de la sala.');
            }

            const { hora_apertura, hora_cierre } = salas[0];
            const [aprH, aprM] = hora_apertura.split(':').map(Number);
            const [cieH, cieM] = hora_cierre.split(':').map(Number);
            
            let minutosActuales = aprH * 60 + aprM;
            const minutesCierre = cieH * 60 + cieM;
            const funcionesACrear = [];

            while (minutosActuales + minutosDuracion <= minutesCierre) {
                const minutosFinPelicula = minutosActuales + minutosDuracion;
                const hInicio = String(Math.floor(minutosActuales / 60)).padStart(2, '0') + ':' + String(minutosActuales % 60).padStart(2, '0') + ':00';
                const hFin = String(Math.floor(minutosFinPelicula / 60)).padStart(2, '0') + ':' + String(minutosFinPelicula % 60).padStart(2, '0') + ':00';

                funcionesACrear.push([peliculaId, parseInt(sala_id), hInicio, hFin]);
                minutosActuales = minutosFinPelicula + MINUTOS_LIMPIEZA;
            }

            if (funcionesACrear.length === 0) {
                return res.send('<h3>La película no cabe en el horario de la sala.</h3>');
            }

            const queryFunciones = 'INSERT INTO funciones (pelicula_id, sala_id, hora_inicio, hora_fin) VALUES ?';
            conexion.query(queryFunciones, [funcionesACrear], (errFunciones) => {
                if (errFunciones) return res.status(500).send('Error al generar las funciones automáticas');
                
                res.send(`
                    <div style="text-align: center; font-family: sans-serif; margin-top: 50px; color: white; background: #141414; padding: 20px;">
                        <h1 style="color: #4CAF50;">¡Película y Funciones creadas! 🎬</h1>
                        <p>Se calcularon automáticamente ${funcionesACrear.length} funciones.</p>
                        <a href="/admin" style="color: #e50914; font-weight: bold; text-decoration: none;">Volver al panel</a>
                    </div>
                `);
            });
        });
    });
});

app.post('/api/admin/cambiar-estado', verificarAdmin, (req, res) => {
    const { pelicula_id, nuevo_estado, sala_id } = req.body;

    conexion.query('UPDATE peliculas SET estado = ? WHERE id = ?', [nuevo_estado, pelicula_id], (err) => {
        if (err) return res.status(500).send('Error al actualizar estado.');

        if (nuevo_estado === 'almacen' || nuevo_estado === 'estreno') {
            conexion.query('DELETE FROM funciones WHERE pelicula_id = ?', [pelicula_id], () => {
                return res.redirect('/admin');
            });
        } 
        else if (nuevo_estado === 'cartelera' && sala_id) {
            conexion.query('DELETE FROM funciones WHERE pelicula_id = ?', [pelicula_id], () => {
                conexion.query('SELECT duracion FROM peliculas WHERE id = ?', [pelicula_id], (err, pRes) => {
                    const minutosDuracion = pRes[0].duracion;

                    conexion.query('SELECT hora_apertura, hora_cierre FROM salas WHERE id = ?', [sala_id], (err, sRes) => {
                        const { hora_apertura, hora_cierre } = sRes[0];
                        const [aprH, aprM] = hora_apertura.split(':').map(Number);
                        const [cieH, cieM] = hora_cierre.split(':').map(Number);
                        
                        let minutosActuales = aprH * 60 + aprM;
                        const minutosCierre = cieH * 60 + cieM;
                        const funcionesACrear = [];

                        while (minutosActuales + minutosDuracion <= minutosCierre) {
                            const minutosFinPelicula = minutosActuales + minutosDuracion;
                            const hInicio = String(Math.floor(minutosActuales / 60)).padStart(2, '0') + ':' + String(minutosActuales % 60).padStart(2, '0') + ':00';
                            const hFin = String(Math.floor(minutosFinPelicula / 60)).padStart(2, '0') + ':' + String(minutosFinPelicula % 60).padStart(2, '0') + ':00';

                            funcionesACrear.push([pelicula_id, parseInt(sala_id), hInicio, hFin]);
                            minutosActuales = minutosFinPelicula + MINUTOS_LIMPIEZA;
                        }

                        if (funcionesACrear.length > 0) {
                            conexion.query('INSERT INTO funciones (pelicula_id, sala_id, hora_inicio, hora_fin) VALUES ?', [funcionesACrear], () => {
                                res.redirect('/admin');
                            });
                        } else {
                            res.send('No cupo en los horarios de la sala.');
                        }
                    });
                });
            });
        } else {
            res.redirect('/admin');
        }
    });
});

app.get('/api/admin/todas-las-peliculas', verificarAdmin, (req, res) => {
    conexion.query('SELECT id, titulo, estado FROM peliculas ORDER BY id DESC', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.post('/api/admin/agregar-combo', verificarAdmin, upload.single('imagenCombo'), (req, res) => {
    if (!req.file) return res.status(400).send('Debes seleccionar una imagen para el combo.');

    const { nombre, precio, descripcion } = req.body;
    const stock = req.body.stock ? parseInt(req.body.stock, 10) : 0; 
    const imagenURL = '/' + req.file.filename;

    const query = 'INSERT INTO combos (nombre, descripcion, precio, imagen, stock) VALUES (?, ?, ?, ?, ?)';
    conexion.query(query, [nombre, descripcion, parseFloat(precio), imagenURL, stock], (err, result) => {
        if (err) {
            console.error("❌ Error al guardar el combo:", err);
            return res.status(500).send('Error interno al guardar el combo.');
        }

        res.send(`
            <div style="text-align: center; font-family: sans-serif; margin-top: 50px; color: white; background: #141414; padding: 20px;">
                <h1 style="color: #4CAF50;">¡Combo Guardado Exitosamente! 🍿🥤</h1>
                <p>El combo <strong>${nombre}</strong> ya está disponible con un stock de ${stock} unidades.</p>
                <a href="/carameleria" style="color: #e50914; font-weight: bold; text-decoration: none;">Volver a Caramelería</a>
            </div>
        `);
    });
});

app.post('/api/admin/eliminar-combo', verificarAdmin, (req, res) => {
    const { combo_id } = req.body;

    const query = 'DELETE FROM combos WHERE id = ?';
    conexion.query(query, [combo_id], (err, result) => {
        if (err) {
            console.error("❌ Error al eliminar el combo:", err);
            return res.status(500).json({ error: 'No se pudo eliminar el combo' });
        }
        res.redirect('/carameleria');
    });
});

app.get('/api/combos', (req, res) => {
    conexion.query('SELECT * FROM combos ORDER BY id DESC', (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al obtener los combos' });
        res.json(results);
    });
});


// 5. APIS PÚBLICAS Y AUXILIARES

app.get('/api/salas', (req, res) => {
    conexion.query('SELECT id, nombre FROM salas', (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al traer salas' });
        res.json(results);
    });
});

app.get('/api/usuario-actual', (req, res) => {
    if (req.session && req.session.nombre) {
        res.json({
            logueado: true,
            nombre: req.session.nombre,
            rol: req.session.rol
        });
    } else {
        res.json({ logueado: false });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => { res.redirect('/'); });
});

app.get('/api/cartelera', (req, res) => {
    const query = `
        SELECT p.id AS pelicula_id, p.titulo, p.duracion, p.genero, p.portada, p.sinopsis,
               f.id AS funcion_id, f.hora_inicio, f.hora_fin, f.sala_id
        FROM peliculas p
        LEFT JOIN funciones f ON p.id = f.pelicula_id
        WHERE p.estado = 'cartelera'
        ORDER BY p.id ASC, f.hora_inicio ASC
    `;
    conexion.query(query, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Error en base de datos' });

        const peliculasMap = {};
        rows.forEach(row => {
            if (!peliculasMap[row.pelicula_id]) {
                peliculasMap[row.pelicula_id] = {
                    id: row.pelicula_id, titulo: row.titulo, duracion: row.duracion,
                    genero: row.genero, portada: row.portada, sinopsis: row.sinopsis, funciones: []
                };
            }
            if (row.funcion_id) {
                peliculasMap[row.pelicula_id].funciones.push({
                    id: row.funcion_id, hora_inicio: row.hora_inicio, hora_fin: row.hora_fin, sala_id: row.sala_id
                });
            }
        });
        res.json(Object.values(peliculasMap));
    });
});

app.get('/api/estrenos', (req, res) => {
    const query = "SELECT id, titulo, duracion, genero, portada, sinopsis FROM peliculas WHERE estado = 'estreno' ORDER BY id DESC";
    conexion.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/comprar/:funcionId', (req, res) => {
    if (!req.session || !req.session.usuarioId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'views', 'comprar.html'));
});

app.get('/api/funcion/:id/asientos', (req, res) => {
    const funcionId = req.params.id;

    const queryInfo = `
        SELECT f.id AS funcion_id, f.hora_inicio, p.titulo, p.portada, s.nombre AS sala, s.capacidad
        FROM funciones f
        JOIN peliculas p ON f.pelicula_id = p.id
        JOIN salas s ON f.sala_id = s.id
        WHERE f.id = ?
    `;

    conexion.query(queryInfo, [funcionId], (err, infoResult) => {
        if (err || infoResult.length === 0) return res.status(404).json({ error: 'Función no encontrada' });

        const queryAsientos = 'SELECT numero_asiento FROM asientos_reservados WHERE funcion_id = ?';
        conexion.query(queryAsientos, [funcionId], (err, asientosResult) => {
            if (err) return res.status(500).json({ error: 'Error al consultar asientos' });

            const ocupados = asientosResult.map(a => a.numero_asiento);
            res.json({
                funcion: infoResult[0],
                asientosOcupados: ocupados
            });
        });
    });
});

app.get('/pelicula/:id/funciones', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'funciones-pelicula.html'));
});

app.get('/api/pelicula/:id/funciones', (req, res) => {
    const peliculaId = req.params.id;

    const queryPeli = 'SELECT * FROM peliculas WHERE id = ?';
    conexion.query(queryPeli, [peliculaId], (err, peliResult) => {
        if (err || peliResult.length === 0) {
            return res.status(404).json({ error: 'Película no encontrada' });
        }

        const queryFunciones = `
            SELECT f.id, f.hora_inicio, s.nombre AS sala_nombre
            FROM funciones f
            JOIN salas s ON f.sala_id = s.id
            WHERE f.pelicula_id = ?
        `;

        conexion.query(queryFunciones, [peliculaId], (err, funcionesResult) => {
            if (err) {
                console.error("Error consultando funciones:", err);
                return res.status(500).json({ error: 'Error al obtener funciones' });
            }

            res.json({
                pelicula: peliResult[0],
                funciones: funcionesResult
            });
        });
    });
});

app.get('/pago', (req, res) => {
    if (!req.session || !req.session.usuarioId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'views', 'pago.html'));
});

// API POST: Procesar Pago y Guardar QR de Texto e Información de la Entrada
// API POST: Procesar Pago y Guardar QR de Texto e Información de la Entrada
app.post('/api/procesar-pago', async (req, res) => {
    if (!req.session || !req.session.usuarioId) {
        return res.status(401).json({ error: 'Debes iniciar sesión para continuar' });
    }

    const { funcionId, asientos, total, metodoPago, referencia } = req.body;
    const usuarioId = req.session.usuarioId;

    if (!asientos || asientos.length === 0) {
        return res.status(400).json({ error: 'No seleccionaste ningún asiento' });
    }

    const asientosStr = asientos.join(', ');
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=Cine-Función-${funcionId}-Asientos-${asientosStr}-Ref-${referencia}`;

    const query = `
        INSERT INTO compras (usuario_id, funcion_id, asientos, referencia, qr_url, monto_total, estado) 
        VALUES (?, ?, ?, ?, ?, ?, 'pagado')
    `;

    conexion.query(query, [usuarioId, funcionId, asientosStr, referencia, qrUrl, total], (err, result) => {
        if (err) {
            console.error("❌ Error detallado al guardar la compra:", err.message);
            return res.status(500).json({ exito: false, error: 'Error al registrar la compra: ' + err.message });
        }

        const compraId = result.insertId;
        const valuesAsientos = asientos.map(a => [compraId, funcionId, a]);
        // Nota: Asegúrate de que tu tabla asientos_reservados tenga la columna compra_id o usa solo funcion_id y numero_asiento según tu diseño previo.
        const queryAsientos = 'INSERT INTO asientos_reservados (compra_id, funcion_id, numero_asiento) VALUES ?';
        
        conexion.query(queryAsientos, [valuesAsientos], (err2) => {
            if (err2) {
                // Si tu tabla asientos_reservados no tiene la columna compra_id, usa esta alternativa de respaldo:
                const queryAsientosSimple = 'INSERT INTO asientos_reservados (funcion_id, numero_asiento) VALUES ?';
                const valuesSimple = asientos.map(a => [funcionId, a]);
                conexion.query(queryAsientosSimple, [valuesSimple], (err3) => {
                    if (err3) console.error("Error al bloquear asientos:", err3);
                });
            }

            res.json({
                exito: true,
                qr: qrUrl
            });
        });
    });
});

app.post('/api/procesar-pago-carameleria', async (req, res) => {
    if (!req.session || !req.session.usuarioId) {
        return res.status(401).json({ error: 'Debes iniciar sesión para comprar en la caramelería' });
    }

    const { comboId, comboNombre, cantidad, total, metodoPago, referencia } = req.body;
    const usuarioId = req.session.usuarioId;

    if (!comboId || !cantidad || cantidad <= 0) {
        return res.status(400).json({ error: 'Selección o cantidad de combos inválida' });
    }

    try {
        const textoQR = `CineCentral | Combo: ${comboNombre} (x${cantidad}) | Total: $${total} | Ref: ${referencia}`;

        let qrDataURI = '';
        try {
            qrDataURI = await QRCode.toDataURL(textoQR);
        } catch (errQR) {
            console.error("❌ Error generando código QR:", errQR);
            return res.status(500).json({ error: 'Error interno generando el QR' });
        }

        // Guardamos los datos del combo directamente en los campos comunes de la tabla compras
        const queryCompra = `
            INSERT INTO compras (usuario_id, asientos, referencia, qr_url, monto_total, estado) 
            VALUES (?, ?, ?, ?, ?, 'pagado')
        `;
        const descripcionCombo = `${comboNombre} (x${cantidad})`;

        conexion.query(queryCompra, [usuarioId, descripcionCombo, referencia, qrDataURI, total], (err, resultCompra) => {
            if (err) {
                console.error("❌ Error SQL al insertar compra de caramelería:", err.message);
                return res.status(500).json({ error: 'Error en BD al guardar la compra: ' + err.message });
            }

            const compraId = resultCompra.insertId;

            // Descontar stock del combo
            const queryStock = 'UPDATE combos SET stock = stock - ? WHERE id = ? AND stock >= ?';
            conexion.query(queryStock, [cantidad, comboId, cantidad], (errStock) => {
                if (errStock) console.error("⚠️ Error actualizando stock en combos:", errStock.message);

                return res.json({
                    exito: true,
                    compraId: compraId,
                    qr: qrDataURI
                });
            });
        });

    } catch (error) {
        console.error("❌ Error general en /api/procesar-pago-carameleria:", error);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// API GET: Consultar las compras del usuario logueado para la vista "Mis Compras"
app.get('/api/usuario/compras', (req, res) => {
    if (!req.session || !req.session.usuarioId) {
        return res.status(401).json({ error: 'No autorizado' });
    }
    
    const usuarioId = req.session.usuarioId;

    const query = `
        SELECT c.id, 
               COALESCE(p.titulo, c.asientos) AS pelicula_titulo, 
               s.nombre AS sala_nombre, 
               f.hora_inicio, 
               CASE WHEN p.id IS NULL THEN 'Combo de Caramelería' ELSE c.asientos END AS asientos, 
               c.referencia, 
               c.qr_url
        FROM compras c
        LEFT JOIN funciones f ON c.funcion_id = f.id
        LEFT JOIN peliculas p ON f.pelicula_id = p.id
        LEFT JOIN salas s ON f.sala_id = s.id
        WHERE c.usuario_id = ?
        ORDER BY c.id DESC
    `;

    conexion.query(query, [usuarioId], (err, results) => {
        if (err) {
            console.error("Error al consultar compras:", err);
            return res.status(500).json({ error: 'Error al obtener las compras' });
        }
        res.json(results);
    });
});

app.post('/api/recuperar-contrasena', async (req, res) => {
    const { email, nuevaPassword } = req.body;

    if (!email || !nuevaPassword) {
        return res.status(400).send('<h3>Todos los campos son obligatorios.</h3><a href="/recuperar-contrasena">Volver</a>');
    }

    try {
        // 1. Verificamos si el correo existe en la base de datos
        const queryCheck = 'SELECT id FROM usuarios WHERE email = ?';
        conexion.query(queryCheck, [email], async (err, results) => {
            if (err) {
                console.error("Error al buscar usuario:", err);
                return res.status(500).send('Error interno en el servidor');
            }

            if (results.length === 0) {
                return res.send(`
                    <div style="text-align:center; font-family:sans-serif; margin-top:50px; background:#141414; color:white;">
                        <h3 style="color:#e50914;">El correo ingresado no está registrado.</h3>
                        <a href="/recuperar-contrasena" style="color:#4CAF50;">Intentar de nuevo</a>
                    </div>
                `);
            }

            // 2. Si existe, encriptamos la nueva contraseña con bcrypt
            const salt = await bcrypt.genSalt(10);
            const passwordHash = await bcrypt.hash(nuevaPassword, salt);

            // 3. Actualizamos la contraseña en la base de datos
            const queryUpdate = 'UPDATE usuarios SET password = ? WHERE email = ?';
            conexion.query(queryUpdate, [passwordHash, email], (errUpdate) => {
                if (errUpdate) {
                    console.error("Error al actualizar la contraseña:", errUpdate);
                    return res.status(500).send('Error al actualizar la contraseña.');
                }

                res.send(`
                    <div style="text-align:center; font-family:sans-serif; margin-top:50px; background:#141414; color:white; padding:30px;">
                        <h1 style="color:#4CAF50;">¡Contraseña Actualizada con Éxito! 🔑</h1>
                        <p>Ya puedes iniciar sesión con tu nueva contraseña.</p>
                        <a href="/login" style="color:#e50914; font-weight:bold; text-decoration:none;">Ir al Login</a>
                    </div>
                `);
            });
        });

    } catch (error) {
        console.error("Error general en recuperación:", error);
        res.status(500).send('Error interno del servidor.');
    }
});

// API GET: Consultar la tasa de cambio actual
app.get('/api/tasa-cambio', (req, res) => {
    conexion.query('SELECT valor FROM configuracion WHERE clave = ?', ['tasa_cambio'], (err, results) => {
        if (err || results.length === 0) {
            return res.json({ tasa: 1.00 }); // Valor por defecto de respaldo
        }
        res.json({ tasa: parseFloat(results[0].valor) });
    });
});

// --- RUTA PARA OBTENER LOS COMBOS DE LA CARAMELERÍA ---
app.get('/api/combos', (req, res) => {
    const query = 'SELECT id, nombre, descripcion, precio, imagen, stock FROM combos';
    conexion.query(query, (err, results) => {
        if (err) {
            console.error("Error al obtener los combos:", err);
            return res.status(500).json({ error: "Error en el servidor al obtener combos" });
        }
        res.json(results);
    });
});

// --- RUTA PARA OBTENER LA TASA BCV ACTUAL ---
app.get('/api/tasa', (req, res) => {
    const query = 'SELECT valor FROM configuracion WHERE clave = ?';
    conexion.query(query, ['tasa_cambio'], (err, results) => {
        if (err) {
            console.error("Error al obtener la tasa:", err);
            return res.status(500).json({ error: "Error en el servidor" });
        }
        if (results.length > 0) {
            res.json({ tasa: parseFloat(results[0].valor) });
        } else {
            res.json({ tasa: 36.50 }); // Valor por defecto si no existe en la BD
        }
    });
});

// --- RUTA PARA ACTUALIZAR LA TASA DE CAMBIO (ADMIN) ---
app.post('/api/admin/actualizar-tasa', verificarAdmin, (req, res) => {
    const { tasa } = req.body;
    
    if (!tasa || isNaN(tasa)) {
        return res.status(400).send('Tasa inválida');
    }

    const query = 'UPDATE configuracion SET valor = ? WHERE clave = ?';
    conexion.query(query, [tasa, 'tasa_cambio'], (err) => {
        if (err) {
            console.error("Error al actualizar tasa:", err);
            return res.status(500).send('Error al actualizar la tasa');
        }
        res.redirect('/admin');
    });
});

// 6. CONTROL DE ARRANQUE DEL SERVIDOR
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto: ${PORT}`);
});