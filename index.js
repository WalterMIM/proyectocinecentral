const express = require('express');
const path = require('path');
const session = require('express-session'); // Para las sesiones
const conexion = require('./conexion'); // Importa tu archivo de conexión
const app = express();
const bcrypt = require('bcryptjs');
const multer = require('multer'); // Gestor de subida de archivos

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

// 6. CONTROL DE ARRANQUE DEL SERVIDOR
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto: ${PORT}`);
});