# app.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload # La usaremos para optimizar
from sqlalchemy import or_
from models import db, Usuario, Rol, Categoria, Documento, LogBusqueda
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import smtplib
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
# Configuración de SQLAlchemy
# Lee la contraseña del .env como ya hacías
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://root:{MYSQL_PASSWORD}@localhost/buscador_docs_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializa la base de datos con nuestra app
db.init_app(app)

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

# --- USER_LOADER (ACTUALIZADO PARA CARGAR AMBOS: ROLES Y PERMISOS) ---
@login_manager.user_loader
def load_user(user_id):
    # Simplemente le pedimos a SQLAlchemy el usuario por su ID.
    # Las relaciones (roles, permisos) se cargarán automáticamente
    # cuando se accedan gracias al 'lazy='dynamic''
    return Usuario.query.get(int(user_id))

# --- ¡NUEVA RUTA Y LÓGICA PARA INDEXAR ARCHIVOS! ---
def actualizar_indice():
    """
    Escanea las carpetas definidas en 'categorias' y actualiza la
    tabla 'documentos' usando SQLAlchemy.
    """
    # ¡IMPORTANTE! Se necesita un contexto de aplicación
    # para que SQLAlchemy funcione fuera de una ruta normal.
    with app.app_context():

        # 1. Obtenemos todas las categorías desde el ORM
        categorias = Categoria.query.all()
        if not categorias:
            print("No hay categorías definidas en la base de datos. Saltando indexación.")
            return 0

        print("Borrando índice de documentos antiguo...")
        # 2. Vaciamos la tabla de documentos usando el ORM
        # (db.session.query(Documento).delete() es más rápido que objeto por objeto)
        db.session.query(Documento).delete()

        nuevos_documentos = []
        archivos_indexados = 0

        # 3. Recorremos cada categoría para buscar archivos
        for categoria in categorias:
            ruta_base = categoria.ruta_carpeta

            if os.path.exists(ruta_base):
                print(f"Indexando categoría: {categoria.nombre} en {ruta_base}...")
                for dirpath, _, filenames in os.walk(ruta_base):
                    for archivo in filenames:
                        ruta_completa = os.path.join(dirpath, archivo)

                        # 4. Creamos los objetos Documento en memoria
                        doc = Documento(
                            nombre_archivo=archivo,
                            ruta_completa=ruta_completa,
                            categoria_id=categoria.id # Usamos el ID del objeto
                        )
                        nuevos_documentos.append(doc)
                        archivos_indexados += 1
            else:
                print(f"ADVERTENCIA: La ruta {ruta_base} para la categoría '{categoria.nombre}' no existe.")

        # 5. Guardamos todos los documentos en la BD en una sola operación
        # (Esto es MUCHO más rápido que hacer un INSERT por cada archivo)
        if nuevos_documentos:
            print(f"Añadiendo {len(nuevos_documentos)} nuevos documentos a la base de datos...")
            db.session.add_all(nuevos_documentos)

        # 6. Confirmamos la transacción
        db.session.commit()

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
    msg['To'] = usuario.email
    
    url_reseteo = url_for('resetear_clave', token=token, _external=True)
    cuerpo = f"""
    <p>Hola {usuario.nombre_completo},</p>
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
        print(f"Correo de reseteo enviado exitosamente a {usuario.email}")
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

        # --- Lógica con SQLAlchemy ---
        # 1. Buscar al usuario por email
        usuario = Usuario.query.filter_by(email=email).first()

        # 2. Verificar si existe y la contraseña es correcta
        if usuario and usuario.check_password(password):

            # 3. Verificar si está activo
            if not usuario.esta_activo:
                flash('Tu cuenta ha sido bloqueada. Por favor, contacta a un administrador.', 'danger')
                return redirect(url_for('login'))

            # 4. Loguear al usuario
            login_user(usuario)
            flash('¡Has iniciado sesión exitosamente!', 'success')

            # 5. Redirigir
            if usuario.debe_cambiar_clave:
                return redirect(url_for('cambiar_clave'))
            else:
                return redirect(url_for('menu'))
        else:
            flash('Email o contraseña incorrectos.', 'danger')

    return render_template('login.html')

@app.route('/menu')
@login_required
def menu():
    # Pasamos los permisos del usuario actual a la plantilla del menú
    return render_template('menu.html', permisos=current_user.permisos)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        email = request.form.get('email')
        password = request.form.get('password')

        # --- Lógica con SQLAlchemy ---
        # 1. Verificamos si el email ya existe
        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('Ese correo electrónico ya está en uso.', 'danger')
            return redirect(url_for('registro'))

        # 2. Creamos el nuevo usuario
        nuevo_usuario = Usuario(nombre_completo=nombre, email=email)
        nuevo_usuario.set_password(password)

        # Nota: No asignamos roles ni permisos aquí, es un registro público.

        # 3. Guardamos en la BD
        db.session.add(nuevo_usuario)
        db.session.commit()

        flash('¡Cuenta creada exitosamente! Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('registro.html')

# --- ¡NUEVA RUTA PARA CERRAR SESIÓN! ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('¡Has cerrado sesión exitosamente!', 'success')
    return redirect(url_for('login'))

# --- BUSCADOR (VERSIÓN FINAL OPTIMIZADA CON ÍNDICE) ---
@app.route('/buscador')
@login_required
def buscador():
    categoria_nombre = request.args.get('categoria', '')
    termino_busqueda = request.args.get('busqueda', '')
    motivo = request.args.get('motivo', '')
    resultados = []

    # --- Lógica con SQLAlchemy ---

    # 1. Obtenemos el objeto Categoria (ya no es un dict)
    categoria_actual = Categoria.query.filter_by(nombre=categoria_nombre).first()

    # 2. Verificamos el permiso (¡ahora mucho más simple!)
    # 'current_user.permisos' es la relación de SQLAlchemy
    if not categoria_actual or categoria_actual not in current_user.permisos:
        flash(f"Acceso denegado a la categoría '{categoria_nombre}'.", 'danger')
        return redirect(url_for('menu'))

    if termino_busqueda and motivo:
        try:
            # 3. Guardamos la búsqueda en el log
            nuevo_log = LogBusqueda(
                usuario_id=current_user.id,
                categoria_buscada=categoria_actual.nombre,
                termino_busqueda=termino_busqueda,
                motivo=motivo
            )
            db.session.add(nuevo_log)

            # 4. Buscamos en la tabla 'documentos' usando el ORM
            resultados_db = Documento.query.filter(
                Documento.categoria == categoria_actual, # Filtramos por el objeto
                Documento.nombre_archivo.like(f"%{termino_busqueda}%")
            ).all()

            # 5. Confirmamos la transacción (guarda el log)
            db.session.commit()

            # 6. Preparamos los resultados para la plantilla
            for fila in resultados_db:
                resultados.append({
                    'nombre_mostrado': os.path.relpath(fila.ruta_completa, categoria_actual.ruta_carpeta),
                    'ruta_completa': fila.ruta_completa
                })
        except Exception as e:
            db.session.rollback() # Revertimos si algo falla (ej: el log)
            print(f"Error durante la búsqueda: {e}")
            flash("Ocurrió un error al realizar la búsqueda.", "danger")

    elif termino_busqueda and not motivo:
        flash("Debe proporcionar un motivo para realizar la búsqueda.", 'danger')

    return render_template('buscador.html', 
                           resultados=resultados, 
                           busqueda_actual=termino_busqueda, 
                           motivo_actual=motivo,
                           categoria=categoria_actual) # Pasamos el objeto

# --- ¡NUEVA RUTA PARA EL PANEL DE ADMINISTRACIÓN! ---
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    # --- Configuración de Paginación ---
    USERS_POR_PAGINA = 10
    pagina_actual = request.args.get('page', 1, type=int)

    # --- Lógica de Filtros (¡ahora como variables!) ---
    filtro_rol_id = request.args.get('rol_id', '')
    filtro_estado = request.args.get('estado', '')
    filtro_busqueda = request.args.get('busqueda', '')

    # --- ¡Aquí comienza la magia de SQLAlchemy! ---

    # 1. Creamos la consulta base.
    # Usamos joinedload() para cargar los roles en la misma consulta
    # y así evitar el problema N+1 en la plantilla.
    query = Usuario.query.options(joinedload(Usuario.roles))

    # 2. Aplicamos los filtros dinámicamente
    if filtro_rol_id:
        # .join() es necesario para filtrar por una relación Many-to-Many
        query = query.join(Usuario.roles).filter(Rol.id == filtro_rol_id)

    if filtro_estado in ['0', '1']:
        # Convertimos '0'/'1' a False/True
        query = query.filter(Usuario.esta_activo == (filtro_estado == '1'))

    if filtro_busqueda:
        # Usamos or_() para buscar en el nombre O en el email
        query = query.filter(
            or_(
                Usuario.nombre_completo.like(f"%{filtro_busqueda}%"),
                Usuario.email.like(f"%{filtro_busqueda}%")
            )
        )

    # 3. Obtenemos el objeto de paginación
    # .paginate() hace el COUNT, LIMIT y OFFSET... ¡todo en una línea!
    pagination = query.order_by(Usuario.nombre_completo).paginate(
        page=pagina_actual, per_page=USERS_POR_PAGINA, error_out=False
    )

    # Los usuarios para la página actual están en .items
    usuarios = pagination.items 

    # 4. Obtenemos todos los roles para el dropdown del filtro
    todos_los_roles = Rol.query.order_by(Rol.nombre).all()

    # 5. Guardamos los filtros para la paginación
    filtros_activos = {
        'rol_id': filtro_rol_id,
        'estado': filtro_estado,
        'busqueda': filtro_busqueda
    }

    return render_template('admin_panel.html', 
                        usuarios=usuarios,         # <-- Para la tabla
                        pagination=pagination,     # <-- ¡El objeto mágico para las macros!
                        pagina_actual=pagina_actual, # <-- Lo mantenemos por ahora
                        total_paginas=pagination.pages, # <-- Obtenido gratis
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
    # 1. Obtenemos el usuario de la BD (o un 404 si no existe)
    usuario = Usuario.query.get_or_404(user_id)

    if request.method == 'POST':
        # 2. Actualizamos los datos simples
        usuario.nombre_completo = request.form.get('nombre_completo')
        usuario.email = request.form.get('email')
        usuario.esta_activo = (request.form.get('esta_activo') == '1')

        # 3. Actualizamos las relaciones (igual que en crear_usuario)
        roles_ids = request.form.getlist('roles')
        permisos_ids = request.form.getlist('permisos')

        usuario.roles = Rol.query.filter(Rol.id.in_(roles_ids)).all()
        usuario.permisos = Categoria.query.filter(Categoria.id.in_(permisos_ids)).all()

        # 4. Guardamos los cambios
        db.session.commit()

        flash(f'Usuario actualizado exitosamente.', 'success')
        return redirect(url_for('admin_panel'))

    # --- LÓGICA GET (¡mira qué simple!) ---
    # Solo necesitamos la lista completa de roles y categorías
    todos_los_roles = Rol.query.order_by(Rol.nombre).all()
    todas_las_categorias = Categoria.query.order_by(Categoria.nombre).all()

    # Pasamos el objeto 'usuario' directamente a la plantilla.
    # Jinja2 podrá acceder a 'usuario.roles' y 'usuario.permisos'
    # para marcar los checkboxes correctos.
    return render_template('editar_usuario.html', 
                           usuario=usuario, 
                           todas_las_categorias=todas_las_categorias, 
                           todos_los_roles=todos_los_roles)

# --- ¡NUEVA RUTA PARA CREAR USUARIOS DESDE EL PANEL DE ADMIN! ---
@app.route('/admin/crear', methods=['GET', 'POST'])
@login_required
@admin_required
def crear_usuario():
    if request.method == 'POST':
        email = request.form.get('email')

        # 1. Verificamos que el email no esté en uso
        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('Ese correo electrónico ya está en uso por otro usuario.', 'danger')
            return redirect(url_for('crear_usuario'))

        # 2. Creamos el nuevo objeto Usuario
        nuevo_usuario = Usuario(
            nombre_completo=request.form.get('nombre_completo'),
            email=email,
            debe_cambiar_clave=(request.form.get('forzar_cambio_clave') == '1')
        )

        # 3. Establecemos la contraseña (usando el método del modelo)
        nuevo_usuario.set_password(request.form.get('password'))

        # 4. Asignamos los roles y permisos (¡la magia del ORM!)
        roles_ids = request.form.getlist('roles')
        permisos_ids = request.form.getlist('permisos')

        # SQLAlchemy es lo suficientemente inteligente como para manejar esto:
        nuevo_usuario.roles = Rol.query.filter(Rol.id.in_(roles_ids)).all()
        nuevo_usuario.permisos = Categoria.query.filter(Categoria.id.in_(permisos_ids)).all()

        # 5. Guardamos en la base de datos
        db.session.add(nuevo_usuario)
        db.session.commit()

        flash('Usuario creado exitosamente.', 'success')
        return redirect(url_for('admin_panel'))

    # --- LÓGICA GET (se simplifica también) ---
    # Simplemente obtenemos todos los roles y categorías
    todos_los_roles = Rol.query.order_by(Rol.nombre).all()
    todas_las_categorias = Categoria.query.order_by(Categoria.nombre).all()

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

    # --- Lógica de Filtros ---
    filtro_usuario_id = request.args.get('usuario_id', '')
    filtro_categoria = request.args.get('categoria', '')
    
    # 1. Consulta base (optimizada con joinedload)
    # Cargamos los datos del 'usuario' en la misma consulta
    query = LogBusqueda.query.options(joinedload(LogBusqueda.usuario))

    # 2. Aplicamos filtros
    if filtro_usuario_id:
        query = query.filter(LogBusqueda.usuario_id == filtro_usuario_id)
    if filtro_categoria:
        query = query.filter(LogBusqueda.categoria_buscada == filtro_categoria)
        
    # 3. Obtenemos el objeto de paginación
    pagination = query.order_by(LogBusqueda.timestamp.desc()).paginate(
        page=pagina_actual, per_page=LOGS_POR_PAGINA, error_out=False
    )
    
    # 4. Obtenemos datos para los dropdowns de filtros
    todos_los_usuarios = Usuario.query.order_by(Usuario.nombre_completo).all()
    todas_las_categorias = Categoria.query.order_by(Categoria.nombre).all()
    
    # 5. Guardamos filtros para la paginación
    filtros_activos = {
        'usuario_id': filtro_usuario_id,
        'categoria': filtro_categoria
    }

    return render_template('ver_logs.html', 
                           logs=pagination.items,      # <-- Usamos los items de la paginación
                           pagination=pagination,    # <-- Pasamos el objeto completo
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

        if not es_contrasena_segura(nueva_pass):
            flash('La contraseña no cumple los requisitos: mínimo 8 caracteres, una mayúscula y un número.', 'danger')
            return redirect(url_for('cambiar_clave'))

        # --- Lógica con SQLAlchemy ---
        # 1. Obtenemos el usuario actual (ya es un objeto SQLAlchemy)
        usuario = Usuario.query.get(current_user.id)

        # 2. Actualizamos la contraseña y la bandera
        usuario.set_password(nueva_pass)
        usuario.debe_cambiar_clave = False

        # 3. Guardamos en la base de datos
        db.session.commit()

        flash('Contraseña actualizada exitosamente. Por favor, inicia sesión de nuevo.', 'success')
        logout_user() # Forzamos el re-login
        return redirect(url_for('login'))

    return render_template('cambiar_clave.html')

@app.route('/solicitar-reseteo', methods=['GET', 'POST'])
def solicitar_reseteo():
    if request.method == 'POST':
        email = request.form.get('email')

        # --- Lógica con SQLAlchemy ---
        # 1. Buscamos al usuario
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario:
            # 2. Generamos token y expiración
            token = secrets.token_hex(16)
            expiracion = datetime.utcnow() + timedelta(hours=1)

            # 3. Asignamos los valores al objeto usuario
            usuario.reset_token = token
            usuario.reset_token_expiracion = expiracion

            # 4. Guardamos en la BD
            db.session.commit()

            # 5. Enviar correo (¡Necesitamos un pequeño ajuste aquí!)
            # Tu función 'enviar_correo_reseteo' espera un diccionario.
            # Vamos a pasarle el objeto 'usuario' y ajustaremos la función.
            enviar_correo_reseteo(usuario, token) # Ajuste en el paso 4

            flash(f'Se ha enviado un enlace para restablecer la contraseña a {email}.', 'success')

        else:
            flash(f'El correo electrónico {email} no se encuentra registrado en el sistema.', 'danger')

        return redirect(url_for('login'))

    return render_template('solicitar_reseteo.html')

@app.route('/resetear-clave/<token>', methods=['GET', 'POST'])
def resetear_clave(token):

    # --- Lógica con SQLAlchemy ---
    # 1. Buscamos al usuario por el token Y que no haya expirado
    usuario = Usuario.query.filter(
        Usuario.reset_token == token,
        Usuario.reset_token_expiracion > datetime.utcnow()
    ).first()

    if not usuario:
        flash('El enlace de restablecimiento es inválido o ha expirado.', 'danger')
        return redirect(url_for('solicitar_reseteo'))

    if request.method == 'POST':
        nueva_pass = request.form.get('nueva_password')
        confirmar_pass = request.form.get('confirmar_password')

        if nueva_pass != confirmar_pass:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('resetear_clave', token=token))

        if not es_contrasena_segura(nueva_pass):
            flash('La contraseña no cumple los requisitos: mínimo 8 caracteres, una mayúscula y un número.', 'danger')
            return redirect(url_for('resetear_clave', token=token))

        # 2. Actualizamos la contraseña y anulamos el token
        usuario.set_password(nueva_pass)
        usuario.reset_token = None
        usuario.reset_token_expiracion = None

        # 3. Guardamos en la BD
        db.session.commit()

        flash('Tu contraseña ha sido actualizada. Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

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