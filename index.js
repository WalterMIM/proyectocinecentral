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


// 3. RUTAS DE AUTENTICACIÓN (POST)

// LOGUEAR USUARIO
// Busca coincidencia directa de correo y contraseña para iniciar la sesión guardando los datos del usuario en la 'session'
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT id, nombre, email, rol FROM usuarios WHERE email = ? AND password = ?';
    conexion.query(query, [email, password], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error interno en el servidor');
        }

        if (results.length > 0) {
            const usuario = results[0];
            req.session.usuarioId = usuario.id;
            req.session.nombre = usuario.nombre;
            req.session.rol = usuario.rol;

            res.redirect('/'); 
        } else {
            res.send('<h3>Correo o contraseña incorrectos.</h3><a href="/login">Volver a intentar</a>');
        }
    });
});

// REGISTRAR USUARIO (MÉTODO DIRECTO REVERTIDO)
// Verifica duplicados de correo, registra el nuevo usuario en texto plano con rol 'cliente' e inicia sesión automáticamente
app.post('/register', async (req, res) => {
    const { nombre, email, password } = req.body;

    try {
        // 1. Verificar si el correo ya existe
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
                // 2. Encriptar la contraseña antes de guardarla (Recomendado ya que usas bcrypt)
                const salt = await bcrypt.genSalt(10);
                const passwordHash = await bcrypt.hash(password, salt);

                // 3. Insertar en la BD (Corregido: 4 columnas = 4 signos de interrogación)
                const queryInsert = 'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)';
                
                conexion.query(queryInsert, [nombre, email, passwordHash, 'cliente'], (errInsert, result) => {
                    if (errInsert) {
                        console.error("❌ Error al guardar usuario:", errInsert);
                        return res.status(500).send('Error al guardar el usuario.');
                    }
                    
                    // 4. Iniciar sesión automáticamente
                    req.session.usuarioId = result.insertId;
                    req.session.nombre = nombre;
                    req.session.rol = 'cliente';

                    // Redireccionar directamente al Home
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

// AGREGAR PELÍCULA Y GENERAR FUNCIONES AUTOMÁTICAS
// Registra la película en la base de datos y, si su estado es 'cartelera', calcula de forma automática e inserta 
// en bucle todas las funciones posibles que quepan en la sala considerando su hora de apertura, cierre y tiempo de limpieza.
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

            // Conversión de horarios (HH:MM) de la sala a minutos totales para el algoritmo de cálculo de franjas
            const { hora_apertura, hora_cierre } = salas[0];
            const [aprH, aprM] = hora_apertura.split(':').map(Number);
            const [cieH, cieM] = hora_cierre.split(':').map(Number);
            
            let minutosActuales = aprH * 60 + aprM;
            const minutesCierre = cieH * 60 + cieM;
            const funcionesACrear = [];

            // Bucle del motor de horarios: calcula bloques de "Inicio - Fin - Limpieza" recurrentemente
            while (minutosActuales + minutosDuracion <= minutesCierre) {
                const minutosFinPelicula = minutosActuales + minutosDuracion;
                const hInicio = String(Math.floor(minutosActuales / 60)).padStart(2, '0') + ':' + String(minutosActuales % 60).padStart(2, '0') + ':00';
                const hFin = String(Math.floor(minutosFinPelicula / 60)).padStart(2, '0') + ':' + String(minutosFinPelicula % 60).padStart(2, '0') + ':00';

                funcionesACrear.push([peliculaId, parseInt(sala_id), hInicio, hFin]);
                minutosActuales = minutosFinPelicula + MINUTOS_LIMPIEZA; // Añade el tiempo muerto para limpieza
            }

            if (funcionesACrear.length === 0) {
                return res.send('<h3>La película no cabe en el horario de la sala.</h3>');
            }

            // Inserción masiva indexada de todas las funciones generadas
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

// API POST CAMBIAR ESTADO
// Modifica el estado de una película ('almacen', 'estreno', 'cartelera'). Si pasa a cartelera, limpia funciones viejas 
// y recalcula el árbol de horarios en la nueva sala asignada.
app.post('/api/admin/cambiar-estado', verificarAdmin, (req, res) => {
    const { pelicula_id, nuevo_estado, sala_id } = req.body;

    conexion.query('UPDATE peliculas SET estado = ? WHERE id = ?', [nuevo_estado, pelicula_id], (err) => {
        if (err) return res.status(500).send('Error al actualizar estado.');

        // Si se remueve de la cartelera activa, se limpian sus funciones asociadas por cascada lógica
        if (nuevo_estado === 'almacen' || nuevo_estado === 'estreno') {
            conexion.query('DELETE FROM funciones WHERE pelicula_id = ?', [pelicula_id], () => {
                return res.redirect('/admin');
            });
        } 
        // Si vuelve a cartelera, recalcula las funciones de la sala asignada
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

// API para listar las películas en el panel inferior
app.get('/api/admin/todas-las-peliculas', verificarAdmin, (req, res) => {
    conexion.query('SELECT id, titulo, estado FROM peliculas ORDER BY id DESC', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});


//  AGREGAR COMBO
// Registra un nuevo combo de comida/bebida con carga de imagen multimedia mediante Multer
app.post('/api/admin/agregar-combo', verificarAdmin, upload.single('imagenCombo'), (req, res) => {
    if (!req.file) return res.status(400).send('Debes seleccionar una imagen para el combo.');

    // 1. Extraemos los datos después de que Multer procesó el formulario
    const { nombre, precio, descripcion } = req.body;
    
    // 2. Forzamos la conversión a entero. Si por alguna razón llega undefined, ponemos 0
    const stock = req.body.stock ? parseInt(req.body.stock, 10) : 0; 
    const imagenURL = '/' + req.file.filename;

    // 3. Insertar en la Base de Datos
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

// 🗑️ 2. NUEVA RUTA POST: ELIMINAR COMBO (ADMIN)
// Elimina físicamente un combo del stock por su identificador primario
app.post('/api/admin/eliminar-combo', verificarAdmin, (req, res) => {
    const { combo_id } = req.body;

    const query = 'DELETE FROM combos WHERE id = ?';
    conexion.query(query, [combo_id], (err, result) => {
        if (err) {
            console.error("❌ Error al eliminar el combo:", err);
            return res.status(500).json({ error: 'No se pudo eliminar el combo' });
        }
        
        // Redirige de vuelta a la caramelería para ver el cambio de inmediato
        res.redirect('/carameleria');
    });
});

// 🍿 API GET: OBTENER TODOS LOS COMBOS (PÚBLICA - Para tu sección de caramelería)
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

// Devuelve el estado actual de la sesión para renderizado dinámico en el Frontend (Navbar/Permisos)
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

// Destruye por completo la sesión en el servidor y redirige al index principal
app.get('/logout', (req, res) => {
    req.session.destroy(() => { res.redirect('/'); });
});

// API DE CARTELERA CON MAPEO ESTRUCTURAL JSON
// Ejecuta un LEFT JOIN para unificar películas con sus funciones mapeadas en cartelera.
// Transforma las filas planas de SQL en un objeto anidado estructurado de películas donde cada una contiene su array de funciones.
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
            // Si la película no ha sido agregada al mapa, inicializa su estructura base
            if (!peliculasMap[row.pelicula_id]) {
                peliculasMap[row.pelicula_id] = {
                    id: row.pelicula_id, titulo: row.titulo, duracion: row.duracion,
                    genero: row.genero, portada: row.portada, sinopsis: row.sinopsis, funciones: []
                };
            }
            // Agrega la función vinculada al array de esa película si existe
            if (row.funcion_id) {
                peliculasMap[row.pelicula_id].funciones.push({
                    id: row.funcion_id, hora_inicio: row.hora_inicio, hora_fin: row.hora_fin, sala_id: row.sala_id
                });
            }
        });
        // Retorna las propiedades transformadas en un array limpio de objetos JSON
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

// 🎟️ 1. RUTA VISUAL: Página de selección de asientos
app.get('/comprar/:funcionId', (req, res) => {
    if (!req.session || !req.session.usuarioId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'views', 'comprar.html'));
});

// 🎟️ 2. API GET: Obtener detalles de la función y asientos ocupados
app.get('/api/funcion/:id/asientos', (req, res) => {
    const funcionId = req.params.id;

    const queryInfo = `
        SELECT f.id AS funcion_id, f.hora_inicio, p.titulo, p.portada, s.nombre AS sala
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

// 🎬 1. RUTA VISUAL: Pagina para ver horarios/funciones de una película específica
app.get('/pelicula/:id/funciones', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'funciones-pelicula.html'));
});

// 🎬 2. API GET: Devuelve datos de la película y sus funciones con sus respectivas salas
app.get('/api/pelicula/:id/funciones', (req, res) => {
    const peliculaId = req.params.id;

    // Obtener detalles de la película
    const queryPeli = 'SELECT * FROM peliculas WHERE id = ?';
    conexion.query(queryPeli, [peliculaId], (err, peliResult) => {
        if (err || peliResult.length === 0) {
            return res.status(404).json({ error: 'Película no encontrada' });
        }

        // Obtener las funciones asignadas a esta película uniendo con la tabla 'salas'
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

// 💳 1. Vista visual de la pantalla de pago
app.get('/pago', (req, res) => {
    if (!req.session || !req.session.usuarioId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'views', 'pago.html'));
});

// 💳 2. API POST: Registrar compra, bloquear asientos y generar el QR
app.post('/api/procesar-pago', async (req, res) => {
    if (!req.session || !req.session.usuarioId) {
        return res.status(401).json({ error: 'Debes iniciar sesión para continuar' });
    }

    const { funcionId, asientos, total, metodoPago, referencia } = req.body;
    const usuarioId = req.session.usuarioId;

    if (!asientos || asientos.length === 0) {
        return res.status(400).json({ error: 'No seleccionaste ningún asiento' });
    }

    try {
        // 1. Guardar la compra en la tabla 'compras'
        const queryCompra = 'INSERT INTO compras (usuario_id, funcion_id, monto_total, estado) VALUES (?, ?, ?, "pagado")';

        conexion.query(queryCompra, [usuarioId, funcionId, total], async (err, resultCompra) => {
            if (err) {
                console.error("❌ Error registrando la compra:", err);
                return res.status(500).json({ error: 'Error al procesar la compra en la BD' });
            }

            const compraId = resultCompra.insertId;

            // 2. Insertar los asientos reservados vinculados a esta compra
            const queryAsientos = 'INSERT INTO asientos_reservados (compra_id, funcion_id, numero_asiento) VALUES ?';
            const valoresAsientos = asientos.map(asiento => [compraId, funcionId, asiento]);

            conexion.query(queryAsientos, [valoresAsientos], async (err) => {
                if (err) {
                    console.error("❌ Error guardando asientos:", err);
                    return res.status(500).json({ error: 'Error al reservar los asientos' });
                }

                // 3. Generar la imagen Data URI del Código QR
                const contenidoQR = `CineCentral | Ticket #${compraId} | Funcion: ${funcionId} | Asientos: ${asientos.join(',')} | Ref: ${referencia}`;
                const qrDataURI = await QRCode.toDataURL(contenidoQR);

                // 4. Guardar el código QR generado en la compra
                const queryUpdateQR = 'UPDATE compras SET codigo_qr = ? WHERE id = ?';
                conexion.query(queryUpdateQR, [qrDataURI, compraId], (err) => {
                    if (err) console.error("Error al asociar el QR:", err);

                    res.json({
                        exito: true,
                        compraId: compraId,
                        qr: qrDataURI
                    });
                });
            });
        });
    } catch (error) {
        console.error("❌ Error general:", error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Asegúrate de tener instalado 'qrcode' (npm install qrcode) y requerido arriba:
// const QRCode = require('qrcode');

app.post('/api/procesar-pago-carameleria', async (req, res) => {
    // 1. Verificación de Sesión
    if (!req.session || !req.session.usuarioId) {
        return res.status(401).json({ error: 'Debes iniciar sesión para comprar en la caramelería' });
    }

    const { comboId, comboNombre, cantidad, total, metodoPago, referencia } = req.body;
    const usuarioId = req.session.usuarioId;

    if (!comboId || !cantidad || cantidad <= 0) {
        return res.status(400).json({ error: 'Selección o cantidad de combos inválida' });
    }

    try {
        // 2. Registrar la compra en la tabla compras
        // NOTA: Si en tu base de datos la columna funcion_id no permite NULL, la ignoramos o pasamos 0/NULL según tu esquema
        const queryCompra = 'INSERT INTO compras (usuario_id, monto_total, estado) VALUES (?, ?, "pagado")';

        conexion.query(queryCompra, [usuarioId, total], async (err, resultCompra) => {
            if (err) {
                console.error("❌ Error SQL al insertar compra en BD:", err.message);
                return res.status(500).json({ error: 'Error en BD al guardar la compra: ' + err.message });
            }

            const compraId = resultCompra.insertId;

            // 3. Generar Código QR
            const textoQR = `CineCentral | Ticket #${compraId} | ${comboNombre} (x${cantidad}) | Total: $${total} | Ref: ${referencia}`;

            let qrDataURI = '';
            try {
                qrDataURI = await QRCode.toDataURL(textoQR);
            } catch (errQR) {
                console.error("❌ Error generando código QR:", errQR);
                return res.status(500).json({ error: 'Error interno generando el QR' });
            }

            // 4. Guardar QR y Actualizar Stock (Si las columnas existen)
            const queryUpdateQR = 'UPDATE compras SET codigo_qr = ? WHERE id = ?';
            conexion.query(queryUpdateQR, [qrDataURI, compraId], (errQR) => {
                if (errQR) console.error("⚠️ Advertencia al actualizar QR en BD:", errQR.message);

                // Descontar stock del combo
                const queryStock = 'UPDATE combos SET stock = stock - ? WHERE id = ? AND stock >= ?';
                conexion.query(queryStock, [cantidad, comboId, cantidad], (errStock, resStock) => {
                    if (errStock) {
                        console.error("⚠️ Error actualizando stock en combos:", errStock.message);
                    }

                    return res.json({
                        exito: true,
                        compraId: compraId,
                        qr: qrDataURI
                    });
                });
            });
        });

    } catch (error) {
        console.error("❌ Error general en /api/procesar-pago-carameleria:", error);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// 6. CONTROL DE ARRANQUE DEL SERVIDOR
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto: ${PORT}`);
});