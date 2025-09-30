# app.py

import os
import pymysql
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

# --- CONFIGURACIÓN INICIAL ---
load_dotenv()
app = Flask(__name__)
# Cargamos la SECRET_KEY desde el archivo .env
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
# Inicializamos Bcrypt para encriptar contraseñas
bcrypt = Bcrypt(app)
# Configuración de la conexión a la base de datos
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': os.getenv('MYSQL_PASSWORD'),
    'db': 'buscador_docs_db',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# --- CONFIGURACIÓN DE FLASK-LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
# Le decimos a Flask-Login cuál es la ruta de nuestra página de login
login_manager.login_view = 'login'

# --- ¡NUEVO DECORADOR PARA PROTEGER RUTAS DE ADMIN! ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Simplemente revisamos si 'admin' está en la lista de roles del usuario
        if 'admin' not in current_user.roles:
            # Si el usuario no es admin, mostramos un error 403 (Prohibido)
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- MODELO DE USUARIO ---
# Esta clase representa a nuestros usuarios. UserMixin le da las propiedades
# que Flask-Login necesita (is_authenticated, is_active, etc.)
class Usuario(UserMixin):
    def __init__(self, id, nombre_completo, email, password_hash, permisos=[], roles=[]):
        self.id = id
        self.nombre_completo = nombre_completo
        self.email = email
        self.password_hash = password_hash
        self.permisos = permisos # Para el buscador
        self.roles = roles       # Para el panel de admin

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# --- USER_LOADER (ACTUALIZADO PARA CARGAR AMBOS: ROLES Y PERMISOS) ---
@login_manager.user_loader
def load_user(user_id):
    conn = pymysql.connect(**db_config)
    try:
        with conn.cursor() as cursor:
            # Obtenemos los datos del usuario
            cursor.execute("SELECT * FROM usuarios WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            if not user_data:
                return None

            # Obtenemos los PERMISOS de búsqueda del usuario
            cursor.execute("""
                SELECT c.nombre, c.ruta_carpeta FROM categorias c
                JOIN usuario_permisos up ON c.id = up.categoria_id
                WHERE up.usuario_id = %s
            """, (user_id,))
            permisos_data = cursor.fetchall()
            
            # Obtenemos los ROLES del usuario
            cursor.execute("""
                SELECT r.nombre FROM roles r
                JOIN usuario_roles ur ON r.id = ur.role_id
                WHERE ur.usuario_id = %s
            """, (user_id,))
            roles_data = cursor.fetchall()
            # Convertimos la lista de diccionarios a una lista simple de nombres de rol
            roles = [item['nombre'] for item in roles_data]
            
            return Usuario(
                id=user_data['id'],
                nombre_completo=user_data['nombre_completo'],
                email=user_data['email'],
                password_hash=user_data['password_hash'],
                permisos=permisos_data,
                roles=roles  # <-- Añadimos los roles al objeto
            )
    finally:
        conn.close()
    return None

# --- ¡NUEVA RUTA Y LÓGICA PARA INDEXAR ARCHIVOS! ---
def actualizar_indice():
    """
    Escanea las carpetas de red definidas en la tabla 'categorias'
    y actualiza la tabla 'documentos' con los archivos encontrados.
    """
    conn = pymysql.connect(**db_config)
    archivos_indexados = 0
    try:
        with conn.cursor() as cursor:
            # 1. Obtenemos todas las categorías (ej: Fichas Clínicas y su ruta de red)
            cursor.execute("SELECT id, ruta_carpeta FROM categorias")
            categorias = cursor.fetchall()

            # 2. Vaciamos la tabla de documentos para empezar desde cero
            cursor.execute("TRUNCATE TABLE documentos")

            # 3. Recorremos cada categoría para buscar archivos
            for categoria in categorias:
                ruta_base = categoria['ruta_carpeta']
                categoria_id = categoria['id']
                
                if os.path.exists(ruta_base):
                    # Usamos os.walk() para recorrer todas las subcarpetas
                    for dirpath, _, filenames in os.walk(ruta_base):
                        for archivo in filenames:
                            # Creamos la ruta completa y el nombre del archivo
                            ruta_completa = os.path.join(dirpath, archivo)
                            nombre_archivo = archivo
                            
                            # Insertamos el archivo en nuestra tabla de índice
                            sql_insert = "INSERT INTO documentos (nombre_archivo, ruta_completa, categoria_id) VALUES (%s, %s, %s)"
                            cursor.execute(sql_insert, (nombre_archivo, ruta_completa, categoria_id))
                            archivos_indexados += 1
            
            conn.commit()
    finally:
        conn.close()
    
    return archivos_indexados

# --- RUTAS DE LA APLICACIÓN ---
@app.route('/')
def index():
    # La ruta raíz ahora redirige al login
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('menu'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = pymysql.connect(**db_config)
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
                user_data = cursor.fetchone()

                # --- ¡CAMBIO AQUÍ! ---
                # 1. Cargamos al usuario candidato
                if user_data:
                    usuario = load_user(user_data['id'])
                    # 2. Usamos el nuevo método para chequear la contraseña
                    if usuario and usuario.check_password(password):
                        login_user(usuario)
                        return redirect(url_for('menu'))

                # Si algo falla (usuario no existe o contraseña incorrecta)
                flash('Email o contraseña incorrectos.', 'danger')
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/menu')
@login_required
def menu():
    # Pasamos los permisos del usuario actual a la plantilla del menú
    return render_template('menu.html', permisos=current_user.permisos)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    # Si el método es POST, significa que el usuario envió el formulario
    if request.method == 'POST':
        # Obtenemos los datos del formulario
        nombre = request.form.get('nombre')
        email = request.form.get('email')
        password = request.form.get('password')

        conn = pymysql.connect(**db_config)
        try:
            with conn.cursor() as cursor:
                # 1. Verificamos si el email ya existe
                cursor.execute("SELECT email FROM usuarios WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash('Ese correo electrónico ya está en uso.', 'danger')
                    return redirect(url_for('registro'))

                # 2. Si no existe, encriptamos la contraseña
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                # 3. Insertamos el nuevo usuario en la base de datos
                cursor.execute(
                    "INSERT INTO usuarios (nombre_completo, email, password_hash) VALUES (%s, %s, %s)",
                    (nombre, email, hashed_password)
                )
            conn.commit()
        finally:
            conn.close()

        # 4. Mostramos un mensaje de éxito y redirigimos al login
        flash('¡Cuenta creada exitosamente! Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    # Si el método es GET, simplemente mostramos la página de registro
    return render_template('registro.html')

# --- ¡NUEVA RUTA PARA CERRAR SESIÓN! ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect(url_for('login'))

# --- BUSCADOR (VERSIÓN FINAL OPTIMIZADA CON ÍNDICE) ---
@app.route('/buscador')
@login_required
def buscador():
    categoria_nombre = request.args.get('categoria', '')
    termino_busqueda = request.args.get('busqueda', '')
    motivo = request.args.get('motivo', '')
    resultados = []

    # Obtenemos la información de la categoría actual (nombre y ruta)
    categoria_actual = next((p for p in current_user.permisos if p['nombre'] == categoria_nombre), None)

    if categoria_nombre and not categoria_actual:
        flash(f"Acceso denegado a la categoría '{categoria_nombre}'.", 'danger')
        return redirect(url_for('menu'))

    if termino_busqueda and motivo:
        if categoria_actual:
            # --- ¡LA LÓGICA DE BÚSQUEDA AHORA ES UNA CONSULTA SQL! ---
            conn = pymysql.connect(**db_config)
            try:
                with conn.cursor() as cursor:
                    # 1. Guardamos la búsqueda en el log
                    sql_log = "INSERT INTO log_busquedas (usuario_id, categoria_buscada, termino_busqueda, motivo) VALUES (%s, %s, %s, %s)"
                    cursor.execute(sql_log, (current_user.id, categoria_actual['nombre'], termino_busqueda, motivo))
                    conn.commit()

                    # 2. Buscamos en la tabla 'documentos' usando LIKE
                    # El formato f"%{...}%" busca el texto en cualquier parte del nombre del archivo
                    sql_search = """
                        SELECT d.nombre_archivo, d.ruta_completa 
                        FROM documentos d
                        JOIN categorias c ON d.categoria_id = c.id
                        WHERE c.nombre = %s AND d.nombre_archivo LIKE %s
                    """
                    cursor.execute(sql_search, (categoria_nombre, f"%{termino_busqueda}%"))
                    resultados_db = cursor.fetchall()

                    # Preparamos los resultados para la plantilla
                    for fila in resultados_db:
                        ruta_base = categoria_actual['ruta_carpeta']
                        resultados.append({
                            'nombre_mostrado': os.path.relpath(fila['ruta_completa'], ruta_base),
                            'ruta_completa': fila['ruta_completa']
                        })
            finally:
                conn.close()

    elif termino_busqueda and not motivo:
        flash("Debe proporcionar un motivo para realizar la búsqueda.", 'danger')

    return render_template('buscador.html', 
                           resultados=resultados, 
                           busqueda_actual=termino_busqueda, 
                           motivo_actual=motivo,
                           categoria=categoria_actual)

# --- ¡NUEVA RUTA PARA EL PANEL DE ADMINISTRACIÓN! ---
@app.route('/admin')
@login_required
@admin_required # Usamos nuestro nuevo guardián
def admin_panel():
    conn = pymysql.connect(**db_config)
    try:
        with conn.cursor() as cursor:
            # Obtenemos todos los usuarios y sus roles
            cursor.execute("""
                SELECT u.id, u.nombre_completo, u.email, u.esta_activo, GROUP_CONCAT(r.nombre SEPARATOR ', ') as roles
                FROM usuarios u
                LEFT JOIN usuario_roles ur ON u.id = ur.usuario_id
                LEFT JOIN roles r ON ur.role_id = r.id
                GROUP BY u.id
            """)
            usuarios = cursor.fetchall()
    finally:
        conn.close()

    return render_template('admin_panel.html', usuarios=usuarios)

@app.route('/admin/indexar')
@login_required
@admin_required
def indexar_archivos():
    # Llamamos a la función que hace el trabajo pesado
    total_archivos = actualizar_indice()
    flash(f'¡Indexación completada! Se encontraron y guardaron {total_archivos} documentos en el índice.', 'success')
    return redirect(url_for('admin_panel'))

# --- ¡RUTA PARA EDITAR USUARIOS ACTUALIZADA! ---
@app.route('/admin/editar/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def editar_usuario(user_id):
    conn = pymysql.connect(**db_config)
    try:
        # --- LÓGICA PARA CUANDO SE ENVÍA EL FORMULARIO (POST) ---
        if request.method == 'POST':
            # 1. Obtenemos todos los datos del formulario
            nuevo_nombre = request.form.get('nombre_completo')
            nuevo_email = request.form.get('email')
            nuevo_estado = request.form.get('esta_activo') # Esto será '1' o '0'
            nuevos_roles_ids = request.form.getlist('roles')
            nuevos_permisos_ids = request.form.getlist('permisos')

            with conn.cursor() as cursor:
                # 2. Actualizamos los datos básicos en la tabla 'usuarios'
                sql_update_user = "UPDATE usuarios SET nombre_completo = %s, email = %s, esta_activo = %s WHERE id = %s"
                cursor.execute(sql_update_user, (nuevo_nombre, nuevo_email, nuevo_estado, user_id))

                # 3. Actualizamos los roles (borrar y re-insertar)
                cursor.execute("DELETE FROM usuario_roles WHERE usuario_id = %s", (user_id,))
                if nuevos_roles_ids:
                    datos_roles = [(user_id, rol_id) for rol_id in nuevos_roles_ids]
                    cursor.executemany("INSERT INTO usuario_roles (usuario_id, role_id) VALUES (%s, %s)", datos_roles)

                # 4. Actualizamos los permisos (borrar y re-insertar)
                cursor.execute("DELETE FROM usuario_permisos WHERE usuario_id = %s", (user_id,))
                if nuevos_permisos_ids:
                    datos_permisos = [(user_id, perm_id) for perm_id in nuevos_permisos_ids]
                    cursor.executemany("INSERT INTO usuario_permisos (usuario_id, categoria_id) VALUES (%s, %s)", datos_permisos)
            
            conn.commit()
            flash(f'Usuario actualizado exitosamente.', 'success')
            return redirect(url_for('admin_panel'))

        # --- LÓGICA PARA CUANDO SE CARGA LA PÁGINA (GET) ---
        with conn.cursor() as cursor:
            # Obtenemos datos del usuario
            cursor.execute("SELECT * FROM usuarios WHERE id = %s", (user_id,))
            usuario = cursor.fetchone()
            
            # Obtenemos todas las categorías posibles
            cursor.execute("SELECT id, nombre FROM categorias")
            todas_las_categorias = cursor.fetchall()
            
            # Obtenemos los permisos que el usuario ya tiene
            cursor.execute("SELECT categoria_id FROM usuario_permisos WHERE usuario_id = %s", (user_id,))
            permisos_actuales = cursor.fetchall()
            permisos_usuario_ids = [p['categoria_id'] for p in permisos_actuales]

            # Obtenemos todos los roles posibles
            cursor.execute("SELECT id, nombre FROM roles")
            todos_los_roles = cursor.fetchall()

            # Obtenemos los roles que el usuario ya tiene
            cursor.execute("SELECT r.nombre FROM roles r JOIN usuario_roles ur ON r.id = ur.role_id WHERE ur.usuario_id = %s", (user_id,))
            roles_actuales = cursor.fetchall()
            roles_usuario_nombres = [r['nombre'] for r in roles_actuales]

    finally:
        conn.close()

    return render_template('editar_usuario.html', 
                           usuario=usuario, 
                           todas_las_categorias=todas_las_categorias, 
                           permisos_usuario=permisos_usuario_ids,
                           todos_los_roles=todos_los_roles,
                           roles_usuario=roles_usuario_nombres)

# --- ¡NUEVA RUTA PARA CREAR USUARIOS DESDE EL PANEL DE ADMIN! ---
@app.route('/admin/crear', methods=['GET', 'POST'])
@login_required
@admin_required
def crear_usuario():
    conn = pymysql.connect(**db_config)
    try:
        # --- LÓGICA PARA CUANDO SE ENVÍA EL FORMULARIO (POST) ---
        if request.method == 'POST':
            nombre = request.form.get('nombre_completo')
            email = request.form.get('email')
            password = request.form.get('password')
            roles_ids = request.form.getlist('roles')
            permisos_ids = request.form.getlist('permisos')

            with conn.cursor() as cursor:
                # 1. Verificamos que el email no esté en uso
                cursor.execute("SELECT email FROM usuarios WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash('Ese correo electrónico ya está en uso por otro usuario.', 'danger')
                    # Si hay error, volvemos a cargar los datos para mostrar el formulario de nuevo
                    return redirect(url_for('crear_usuario'))

                # 2. Encriptamos la contraseña y creamos el usuario
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor.execute("INSERT INTO usuarios (nombre_completo, email, password_hash) VALUES (%s, %s, %s)",
                               (nombre, email, hashed_password))
                
                # 3. Obtenemos el ID del usuario recién creado
                new_user_id = cursor.lastrowid

                # 4. Asignamos los roles y permisos seleccionados
                if roles_ids:
                    datos_roles = [(new_user_id, rol_id) for rol_id in roles_ids]
                    cursor.executemany("INSERT INTO usuario_roles (usuario_id, role_id) VALUES (%s, %s)", datos_roles)
                
                if permisos_ids:
                    datos_permisos = [(new_user_id, perm_id) for perm_id in permisos_ids]
                    cursor.executemany("INSERT INTO usuario_permisos (usuario_id, categoria_id) VALUES (%s, %s)", datos_permisos)

            conn.commit()
            flash('Usuario creado exitosamente.', 'success')
            return redirect(url_for('admin_panel'))

        # --- LÓGICA PARA CUANDO SE CARGA LA PÁGINA (GET) ---
        # Necesitamos cargar los roles y categorías para mostrarlos en los checkboxes
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, nombre FROM roles")
            todos_los_roles = cursor.fetchall()
            cursor.execute("SELECT id, nombre FROM categorias")
            todas_las_categorias = cursor.fetchall()
    finally:
        conn.close()

    return render_template('crear_usuario.html', 
                           todos_los_roles=todos_los_roles, 
                           todas_las_categorias=todas_las_categorias)

# --- ¡RUTA PARA SERVIR ARCHIVOS ACTUALIZADA! ---
# Ahora es más flexible para manejar rutas de red complejas
@app.route('/documentos')
@login_required
def servir_documento():
    # Obtenemos la ruta completa del archivo desde los parámetros de la URL
    ruta_archivo = request.args.get('ruta', '')
    if not ruta_archivo:
        abort(404)

    # Verificación de seguridad: Asegurarnos de que el usuario tiene permiso para la carpeta base de este archivo
    carpetas_permitidas = [p['ruta_carpeta'] for p in current_user.permisos]
    tiene_permiso = any(ruta_archivo.startswith(base) for base in carpetas_permitidas)

    if not tiene_permiso or not os.path.exists(ruta_archivo):
        abort(403) # Acceso prohibido si no tiene permiso o el archivo no existe

    # Extraemos el directorio y el nombre del archivo
    directorio, nombre_archivo = os.path.split(ruta_archivo)
    return send_from_directory(directorio, nombre_archivo)

# --- ¡NUEVA RUTA PARA VISUALIZAR LOS LOGS! ---
@app.route('/admin/logs')
@login_required
@admin_required
def ver_logs():
    conn = pymysql.connect(**db_config)
    try:
        with conn.cursor() as cursor:
            # Hacemos un JOIN para obtener el nombre del usuario en lugar de solo su ID
            sql = """
                SELECT l.*, u.nombre_completo 
                FROM log_busquedas l
                JOIN usuarios u ON l.usuario_id = u.id
                ORDER BY l.timestamp DESC
            """
            cursor.execute(sql)
            logs = cursor.fetchall()
    finally:
        conn.close()
    
    return render_template('ver_logs.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)