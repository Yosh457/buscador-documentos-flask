# app.py

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import smtplib
import pymysql
import math
import secrets
import re
import sys
import numpy as np
import pydicom
from pydicom.pixel_data_handlers.util import apply_voi_lut
from PIL import Image
import io
import base64
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for, flash, abort, send_from_directory, send_file, render_template_string, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

# --- FUNCIÓN PARA RESOLVER RUTAS EN EL EJECUTABLE ---
def resource_path(relative_path):
    """ Obtiene la ruta absoluta al recurso, funciona para desarrollo y para PyInstaller """
    try:
        # PyInstaller crea una carpeta temporal y guarda la ruta en _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- CONFIGURACIÓN INICIAL ---
load_dotenv()
# ¡LÍNEA MODIFICADA! Le decimos a Flask dónde buscar las carpetas
app = Flask(__name__,
            static_folder=resource_path('static'),
            template_folder=resource_path('templates'))

# Carpeta donde guardas los DICOM (ajústala a tu ruta)
DICOM_FOLDER = "dicoms"

# Cache temporal en memoria para no reabrir el mismo archivo a cada request
cache_series = {}

def load_dicom_series(doc_id):
    """
    Carga un archivo DICOM (o serie si fuese el caso).
    Devuelve un diccionario con 'frames' (lista de numpy arrays) y metadata.
    """
    if doc_id in cache_series:
        return cache_series[doc_id]

    path = os.path.join(DICOM_FOLDER, doc_id)
    if not os.path.exists(path):
        abort(404, f"No existe el archivo {path}")

    ds = pydicom.dcmread(path)

    frames = []
    if hasattr(ds, "NumberOfFrames") and int(ds.NumberOfFrames) > 1:
        # Multi-frame en un solo archivo
        arr = ds.pixel_array
        for i in range(arr.shape[0]):
            frames.append(arr[i])
    else:
        # Imagen única
        frames.append(ds.pixel_array)

    series = {"frames": frames}
    cache_series[doc_id] = series
    return series


def frame_to_base64(frame):
    """Convierte un frame numpy a PNG base64."""
    if frame.dtype != np.uint8:
        frame = (frame.astype(np.float32) / frame.max() * 255).astype(np.uint8)
    img = Image.fromarray(frame)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

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

# --- CONFIGURACIÓN DE LA DURACIÓN DE LA SESIÓN ---
# Establecemos que las sesiones duren 5 minutos.
app.permanent_session_lifetime = timedelta(minutes=5)

@app.before_request
def make_session_permanent():
    # Le decimos a Flask que use la duración que configuramos.
    session.permanent = True

# --- CONTROL DE CACHÉ PARA EVITAR EL "BOTÓN ATRÁS" ---
@app.after_request
def add_header(response):
    # Estas cabeceras le ordenan al navegador no guardar la página en caché.
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# --- MODELO DE USUARIO ---
# Esta clase representa a nuestros usuarios. UserMixin le da las propiedades
# que Flask-Login necesita (is_authenticated, is_active, etc.)
class Usuario(UserMixin):
    def __init__(self, id, nombre_completo, email, password_hash, esta_activo, debe_cambiar_clave, permisos=[], roles=[]):
        self.id = id
        self.nombre_completo = nombre_completo
        self.email = email
        self.password_hash = password_hash
        self.esta_activo = esta_activo
        self.debe_cambiar_clave = debe_cambiar_clave
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
                esta_activo=user_data['esta_activo'],
                debe_cambiar_clave=user_data['debe_cambiar_clave'],
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

# --- ¡NUEVA FUNCIÓN PARA ENVIAR CORREOS DE RESETEO! ---
def enviar_correo_reseteo(usuario, token):
    remitente = os.getenv("EMAIL_USUARIO")
    contrasena = os.getenv("EMAIL_CONTRASENA")
    
    # Verificación para asegurarnos de que las credenciales se cargaron
    if not remitente or not contrasena:
        print("ERROR: Asegúrate de que EMAIL_USUARIO y EMAIL_CONTRASENA están en tu archivo .env")
        return

    msg = MIMEMultipart()
    msg['Subject'] = 'Restablecimiento de Contraseña - Buscador de Documentos'
    msg['From'] = f"Sistema Buscador <{remitente}>"
    # ¡CORRECCIÓN! El destinatario es el email del usuario que lo solicitó.
    msg['To'] = usuario['email']
    
    url_reseteo = url_for('resetear_clave', token=token, _external=True)
    cuerpo = f"""
    <p>Hola {usuario['nombre_completo']},</p>
    <p>Hemos recibido una solicitud para restablecer tu contraseña. Haz clic en el siguiente enlace para continuar:</p>
    <p><a href="{url_reseteo}" style="padding: 10px 15px; background-color: #0d6efd; color: white; text-decoration: none; border-radius: 5px;">Restablecer mi contraseña</a></p>
    <p>Si no solicitaste esto, puedes ignorar este correo.</p>
    <p>El enlace expirará en 1 hora.</p>
    """
    msg.attach(MIMEText(cuerpo, 'html'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(remitente, contrasena)
        server.send_message(msg)
        server.quit()
        print(f"Correo de reseteo enviado exitosamente a {usuario['email']}")
    except Exception as e:
        print(f"Error al enviar correo de reseteo: {e}")

# --- NUEVA FUNCIÓN PARA VALIDAR CONTRASEÑAS ---
def es_contrasena_segura(password):
    """Verifica que la contraseña cumpla con los requisitos de seguridad."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password): # Al menos una mayúscula
        return False
    if not re.search(r"[0-9]", password): # Al menos un número
        return False
    return True

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
                # La consulta ahora también trae el estado 'esta_activo'
                cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
                user_data = cursor.fetchone()

                # 1. Verificamos si el usuario existe y la contraseña es correcta
                if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
                    
                    # --- ¡NUEVA VERIFICACIÓN DE ESTADO! ---
                    # 2. Verificamos si la cuenta está activa
                    if not user_data['esta_activo']:
                        flash('Tu cuenta ha sido bloqueada. Por favor, contacta a un administrador.', 'danger')
                        return redirect(url_for('login'))
                    
                    # 3. Si todo está bien, creamos el objeto y lo logueamos
                    usuario = load_user(user_data['id'])
                    login_user(usuario)
                    
                    # --- ¡LÓGICA DE REDIRECCIÓN FINAL! ---
                    if usuario.debe_cambiar_clave:
                        return redirect(url_for('cambiar_clave'))
                    else:
                        return redirect(url_for('menu'))
                else:
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
@admin_required
def admin_panel():
    # --- Configuración de Paginación ---
    USERS_POR_PAGINA = 10
    pagina_actual = request.args.get('page', 1, type=int)
    offset = (pagina_actual - 1) * USERS_POR_PAGINA

    # --- Lógica de Filtros y Búsqueda ---
    filtro_rol_id = request.args.get('rol_id', '')
    filtro_estado = request.args.get('estado', '')
    filtro_busqueda = request.args.get('busqueda', '')
    
    clausulas_where = []
    parametros = []
    
    base_sql = """
        FROM usuarios u
        LEFT JOIN usuario_roles ur ON u.id = ur.usuario_id
        LEFT JOIN roles r ON ur.role_id = r.id
    """
    
    if filtro_rol_id:
        clausulas_where.append("ur.role_id = %s")
        parametros.append(filtro_rol_id)
    if filtro_estado in ['0', '1']:
        clausulas_where.append("u.esta_activo = %s")
        parametros.append(filtro_estado)
    # --- ¡NUEVA LÓGICA DE BÚSQUEDA! ---
    if filtro_busqueda:
        # Buscamos en el nombre O en el email
        clausulas_where.append("(u.nombre_completo LIKE %s OR u.email LIKE %s)")
        parametros.extend([f"%{filtro_busqueda}%", f"%{filtro_busqueda}%"])
        
    where_sql = "WHERE " + " AND ".join(clausulas_where) if clausulas_where else ""

    conn = pymysql.connect(**db_config)
    try:
        with conn.cursor() as cursor:
            # 1. Obtenemos el TOTAL de usuarios que coinciden con los filtros
            sql_count = f"SELECT COUNT(DISTINCT u.id) as total {base_sql} {where_sql}"
            cursor.execute(sql_count, tuple(parametros))
            total_usuarios = cursor.fetchone()['total']
            total_paginas = math.ceil(total_usuarios / USERS_POR_PAGINA)

            # 2. Obtenemos la PORCIÓN de usuarios para la página actual
            sql_select = f"""
                SELECT u.id, u.nombre_completo, u.email, u.esta_activo, GROUP_CONCAT(r.nombre SEPARATOR ', ') as roles
                {base_sql}
                {where_sql}
                GROUP BY u.id
                ORDER BY u.nombre_completo
                LIMIT %s OFFSET %s
            """
            cursor.execute(sql_select, tuple(parametros) + (USERS_POR_PAGINA, offset))
            usuarios = cursor.fetchall()
            
            # 3. Obtenemos todos los roles para llenar el dropdown del filtro
            cursor.execute("SELECT id, nombre FROM roles ORDER BY nombre")
            todos_los_roles = cursor.fetchall()
    finally:
        conn.close()
    
    filtros_activos = {
        'rol_id': filtro_rol_id,
        'estado': filtro_estado,
        'busqueda': filtro_busqueda
    }

    return render_template('admin_panel.html', 
                           usuarios=usuarios,
                           pagina_actual=pagina_actual,
                           total_paginas=total_paginas,
                           todos_los_roles=todos_los_roles,
                           filtros=filtros_activos)

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
            forzar_cambio = request.form.get('forzar_cambio_clave') == '1'
            
            with conn.cursor() as cursor:
                # 1. Verificamos que el email no esté en uso
                cursor.execute("SELECT email FROM usuarios WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash('Ese correo electrónico ya está en uso por otro usuario.', 'danger')
                    # Si hay error, volvemos a cargar los datos para mostrar el formulario de nuevo
                    return redirect(url_for('crear_usuario'))

                # 2. Encriptamos la contraseña y creamos el usuario
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor.execute("INSERT INTO usuarios (nombre_completo, email, password_hash, debe_cambiar_clave) VALUES (%s, %s, %s, %s)",
                               (nombre, email, hashed_password, forzar_cambio))

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
    ruta_archivo = request.args.get('ruta', '')
    if not ruta_archivo:
        abort(404)

    # Verificación de seguridad (misma lógica)
    carpetas_permitidas = [p['ruta_carpeta'] for p in current_user.permisos]
    tiene_permiso = any(ruta_archivo.startswith(base) for base in carpetas_permitidas)
    if not tiene_permiso or not os.path.exists(ruta_archivo):
        abort(403)

    directorio, nombre_archivo = os.path.split(ruta_archivo)

    # --- DETECCIÓN DICOM ---
    if nombre_archivo.lower().endswith(('.dcm', '.dicom')):
        try:
            dcm_file = pydicom.dcmread(ruta_archivo)

            # --- CASO 1: Multi-frame DICOM ---
            num_frames = int(dcm_file.get("NumberOfFrames", 1))

            if num_frames > 1:
                print(f"📸 Multi-frame detectado ({num_frames} imágenes en 1 archivo)")
                frames = dcm_file.pixel_array
                imagenes = []

                for i in range(num_frames):
                    frame = frames[i].astype(float)
                    if frame.max() > 0:
                        frame = (np.maximum(frame, 0) / frame.max()) * 255.0
                    frame = frame.astype(np.uint8)
                    img = Image.fromarray(frame)
                    if img.mode != 'RGB':
                        img = img.convert('RGB')
                    buffer = io.BytesIO()
                    img.save(buffer, 'PNG', quality=95)
                    buffer.seek(0)
                    imagenes.append(buffer.getvalue())

            else:
                # --- CASO 2: Serie de archivos DICOM ---
                print("📂 Buscando serie DICOM en la carpeta...")
                ds = dcm_file
                series_uid = ds.get("SeriesInstanceUID")
                carpeta = Path(directorio)
                archivos_serie = sorted(
                    [f for f in carpeta.glob("*.dcm") if pydicom.dcmread(f, stop_before_pixels=True).get("SeriesInstanceUID") == series_uid],
                    key=lambda f: pydicom.dcmread(f, stop_before_pixels=True).get("InstanceNumber", 0)
                )

                if len(archivos_serie) > 1:
                    print(f"📚 Serie detectada: {len(archivos_serie)} archivos")

                    imagenes = []
                    for f in archivos_serie:
                        ds = pydicom.dcmread(f)
                        pixels = ds.pixel_array.astype(float)
                        if pixels.max() > 0:
                            pixels = (np.maximum(pixels, 0) / pixels.max()) * 255.0
                        pixels = pixels.astype(np.uint8)
                        img = Image.fromarray(pixels)
                        if img.mode != 'RGB':
                            img = img.convert('RGB')
                        buffer = io.BytesIO()
                        img.save(buffer, 'PNG', quality=95)
                        buffer.seek(0)
                        imagenes.append(buffer.getvalue())

                else:
                    # --- Solo una imagen ---
                    pixels = dcm_file.pixel_array.astype(float)
                    if pixels.max() > 0:
                        pixels = (np.maximum(pixels, 0) / pixels.max()) * 255.0
                    pixels = pixels.astype(np.uint8)
                    image = Image.fromarray(pixels)
                    if image.mode != 'RGB':
                        image = image.convert('RGB')
                    buffer = io.BytesIO()
                    image.save(buffer, 'PNG', quality=95)
                    buffer.seek(0)
                    imagenes = [buffer.getvalue()]

            # --- Generar HTML con slider ---
            html_slider = """
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <title>Visor DICOM</title>
                <style>
                    body { background: #000; color: white; text-align: center; font-family: sans-serif; margin: 0; }
                    img { max-width: 90vw; max-height: 90vh; display: block; margin: auto; border-radius: 10px; }
                    button { background: #333; color: white; border: none; padding: 10px 20px; margin: 10px; border-radius: 8px; cursor: pointer; }
                    button:hover { background: #555; }
                    .controls { position: fixed; bottom: 20px; width: 100%; display: flex; justify-content: center; gap: 10px; }
                </style>
            </head>
            <body>
                <img id="dicomImage" src="data:image/png;base64,{{ imagenes[0] }}" alt="DICOM">
                <div class="controls">
                    <button onclick="prev()">⬅ Anterior</button>
                    <span id="contador">1 / {{ imagenes|length }}</span>
                    <button onclick="next()">Siguiente ➡</button>
                </div>
                <script>
                    const imagenes = {{ imagenes|tojson }};
                    let index = 0;
                    const imgTag = document.getElementById("dicomImage");
                    const contador = document.getElementById("contador");
                    function update() {
                        imgTag.src = "data:image/png;base64," + imagenes[index];
                        contador.textContent = (index+1) + " / " + imagenes.length;
                    }
                    function next() {
                        if (index < imagenes.length - 1) { index++; update(); }
                    }
                    function prev() {
                        if (index > 0) { index--; update(); }
                    }
                    document.addEventListener("wheel", e => {
                        if (e.deltaY > 0) next();
                        else prev();
                    });
                </script>
            </body>
            </html>
            """

            import base64
            imagenes_base64 = [base64.b64encode(img).decode('utf-8') for img in imagenes]
            return render_template_string(html_slider, imagenes=imagenes_base64)

        except Exception as e:
            print(f"❌ Error al procesar el archivo DICOM '{ruta_archivo}': {e}")
            abort(500)

    # --- No es DICOM ---
    return send_file(ruta_archivo, as_attachment=False)

# --- ¡NUEVA RUTA PARA VISUALIZAR LOS LOGS (CON FILTROS Y PAGINACIÓN)! ---
@app.route('/admin/logs')
@login_required
@admin_required
def ver_logs():
    # --- Configuración de Paginación ---
    LOGS_POR_PAGINA = 15
    pagina_actual = request.args.get('page', 1, type=int)
    offset = (pagina_actual - 1) * LOGS_POR_PAGINA

    # --- Lógica de Filtros ---
    filtro_usuario_id = request.args.get('usuario_id', '')
    filtro_categoria = request.args.get('categoria', '')
    
    # Construimos la consulta SQL dinámicamente para seguridad
    clausulas_where = []
    parametros = []
    
    if filtro_usuario_id:
        clausulas_where.append("l.usuario_id = %s")
        parametros.append(filtro_usuario_id)
    if filtro_categoria:
        clausulas_where.append("l.categoria_buscada = %s")
        parametros.append(filtro_categoria)
        
    where_sql = " AND ".join(clausulas_where) if clausulas_where else "1=1"

    conn = pymysql.connect(**db_config)
    try:
        with conn.cursor() as cursor:
            # 1. Obtenemos el TOTAL de registros que coinciden con los filtros (para calcular las páginas)
            sql_count = f"SELECT COUNT(l.id) as total FROM log_busquedas l WHERE {where_sql}"
            cursor.execute(sql_count, tuple(parametros))
            total_logs = cursor.fetchone()['total']
            total_paginas = math.ceil(total_logs / LOGS_POR_PAGINA)

            # 2. Obtenemos la PORCIÓN de registros para la página actual
            sql_select = f"""
                SELECT l.*, u.nombre_completo 
                FROM log_busquedas l
                JOIN usuarios u ON l.usuario_id = u.id
                WHERE {where_sql}
                ORDER BY l.timestamp DESC
                LIMIT %s OFFSET %s
            """
            cursor.execute(sql_select, tuple(parametros) + (LOGS_POR_PAGINA, offset))
            logs = cursor.fetchall()
            
            # 3. Obtenemos todos los usuarios y categorías para llenar los dropdowns de los filtros
            cursor.execute("SELECT id, nombre_completo FROM usuarios ORDER BY nombre_completo")
            todos_los_usuarios = cursor.fetchall()
            cursor.execute("SELECT nombre FROM categorias ORDER BY nombre")
            todas_las_categorias = cursor.fetchall()
    finally:
        conn.close()
    
    # Guardamos los filtros actuales para pasarlos a los enlaces de paginación
    filtros_activos = {
        'usuario_id': filtro_usuario_id,
        'categoria': filtro_categoria
    }

    return render_template('ver_logs.html', 
                           logs=logs,
                           pagina_actual=pagina_actual,
                           total_paginas=total_paginas,
                           todos_los_usuarios=todos_los_usuarios,
                           todas_las_categorias=todas_las_categorias,
                           filtros=filtros_activos)

@app.route('/cambiar-clave', methods=['GET', 'POST'])
@login_required
def cambiar_clave():
    if request.method == 'POST':
        nueva_pass = request.form.get('nueva_password')
        confirmar_pass = request.form.get('confirmar_password')

        if nueva_pass != confirmar_pass:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('cambiar_clave'))

        # --- ¡NUEVA VALIDACIÓN DE SEGURIDAD EN EL BACKEND! ---
        if not es_contrasena_segura(nueva_pass):
            flash('La contraseña no cumple los requisitos: mínimo 8 caracteres, una mayúscula y un número.', 'danger')
            return redirect(url_for('cambiar_clave'))
        
        # Encriptamos y actualizamos la contraseña
        hashed_password = bcrypt.generate_password_hash(nueva_pass).decode('utf-8')
        conn = pymysql.connect(**db_config)
        try:
            with conn.cursor() as cursor:
                # Actualizamos la contraseña y desactivamos la bandera de cambio
                sql = "UPDATE usuarios SET password_hash = %s, debe_cambiar_clave = 0 WHERE id = %s"
                cursor.execute(sql, (hashed_password, current_user.id))
            conn.commit()
        finally:
            conn.close()

        flash('Contraseña actualizada exitosamente. Por favor, inicia sesión de nuevo.', 'success')
        logout_user() # Cerramos la sesión para forzar un nuevo login con la nueva clave
        return redirect(url_for('login'))

    return render_template('cambiar_clave.html')

@app.route('/solicitar-reseteo', methods=['GET', 'POST'])
def solicitar_reseteo():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = pymysql.connect(**db_config)
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
                usuario = cursor.fetchone()
                if usuario:
                    # Generar token seguro y fecha de expiración
                    token = secrets.token_hex(16)
                    expiracion = datetime.utcnow() + timedelta(hours=1)

                    # Guardar token en la BD
                    sql_update = "UPDATE usuarios SET reset_token = %s, reset_token_expiracion = %s WHERE id = %s"
                    cursor.execute(sql_update, (token, expiracion, usuario['id']))
                    conn.commit()

                    # Enviar correo
                    enviar_correo_reseteo(usuario, token)

            flash('Si tu correo está en nuestro sistema, recibirás un enlace para restablecer tu contraseña.', 'info')
            return redirect(url_for('login'))
        finally:
            conn.close()
    return render_template('solicitar_reseteo.html')

@app.route('/resetear-clave/<token>', methods=['GET', 'POST'])
def resetear_clave(token):
    conn = pymysql.connect(**db_config)
    try:
        with conn.cursor() as cursor:
            # Buscar usuario por token y verificar que no haya expirado
            sql_find = "SELECT * FROM usuarios WHERE reset_token = %s AND reset_token_expiracion > %s"
            cursor.execute(sql_find, (token, datetime.utcnow()))
            usuario = cursor.fetchone()

            if not usuario:
                flash('El enlace de restablecimiento es inválido o ha expirado.', 'danger')
                return redirect(url_for('solicitar_reseteo'))

            if request.method == 'POST':
                nueva_pass = request.form.get('nueva_password')
                confirmar_pass = request.form.get('confirmar_password')

                if nueva_pass != confirmar_pass:
                    flash('Las contraseñas no coinciden.', 'danger')
                    return redirect(url_for('resetear_clave', token=token))

                # --- ¡NUEVA VALIDACIÓN DE SEGURIDAD EN EL BACKEND! ---
                if not es_contrasena_segura(nueva_pass):
                    flash('La contraseña no cumple los requisitos: mínimo 8 caracteres, una mayúscula y un número.', 'danger')
                    return redirect(url_for('resetear_clave', token=token))

                # Encriptamos y actualizamos la contraseña
                hashed_password = bcrypt.generate_password_hash(nueva_pass).decode('utf-8')
                # Actualizar contraseña y anular token
                sql_update = "UPDATE usuarios SET password_hash = %s, reset_token = NULL, reset_token_expiracion = NULL WHERE id = %s"
                cursor.execute(sql_update, (hashed_password, usuario['id']))
                conn.commit()

                flash('Tu contraseña ha sido actualizada. Ya puedes iniciar sesión.', 'success')
                return redirect(url_for('login'))
    finally:
        conn.close()

    return render_template('resetear_clave.html')

@app.route("/documentos/<doc_id>")
def visor(doc_id):
    """
    Página del visor: solo carga el HTML con el esqueleto.
    """
    return render_template("visor_dicom.html", doc_id=doc_id)


@app.route("/api/documentos/<doc_id>/frames_count")
def frames_count(doc_id):
    """
    Devuelve el número total de frames de un documento DICOM.
    """
    series = load_dicom_series(doc_id)
    return jsonify({"total_frames": len(series["frames"])})


@app.route("/api/documentos/<doc_id>/frame/<int:frame_index>")
def get_frame(doc_id, frame_index):
    """
    Devuelve un frame específico como imagen base64.
    """
    series = load_dicom_series(doc_id)
    frames = series["frames"]
    if frame_index < 0 or frame_index >= len(frames):
        abort(404, "Frame fuera de rango")

    img_b64 = frame_to_base64(frames[frame_index])
    return jsonify({"frame_index": frame_index, "image_base64": img_b64})

# --- INDEXACIÓN AUTOMÁTICA AL INICIAR LA APLICACIÓN ---
# Esta condición es un truco para asegurar que la indexación se ejecute
# solo una vez cuando inicias el servidor, y no cada vez que el modo
# de depuración recarga el archivo.
if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
    print("Iniciando indexación de archivos al arrancar...")
    try:
        # Llamamos a la función de indexación
        total = actualizar_indice()
        print(f"Indexación inicial completada. Se encontraron {total} archivos.")
    except Exception as e:
        print(f"ERROR durante la indexación inicial: {e}")
        
if __name__ == '__main__':
    app.run(debug=True)