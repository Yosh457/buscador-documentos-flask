# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

# --- Tablas de Asociación (Muchos a Muchos) ---
# Define las tablas que conectan usuarios con roles y permisos.

usuario_roles = db.Table('usuario_roles',
    db.Column('usuario_id', db.Integer, db.ForeignKey('usuarios.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

usuario_permisos = db.Table('usuario_permisos',
    db.Column('usuario_id', db.Integer, db.ForeignKey('usuarios.id'), primary_key=True),
    db.Column('categoria_id', db.Integer, db.ForeignKey('categorias.id'), primary_key=True)
)

# --- Modelos Principales ---

class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nombre_completo = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    esta_activo = db.Column(db.Boolean, nullable=False, default=True)
    debe_cambiar_clave = db.Column(db.Boolean, nullable=False, default=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiracion = db.Column(db.DateTime, nullable=True)
    fecha_creacion = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relaciones (Muchos a Muchos)
    # SQLAlchemy usará las tablas de asociación que definimos arriba.
    roles = db.relationship('Rol', secondary=usuario_roles,
                            back_populates='usuarios', lazy='dynamic')
    
    permisos = db.relationship('Categoria', secondary=usuario_permisos,
                               back_populates='usuarios', lazy='dynamic')
    
    # Relación (Uno a Muchos)
    # Un usuario puede tener muchos logs de búsqueda.
    logs = db.relationship('LogBusqueda', back_populates='usuario', lazy='dynamic')

    # Métodos para contraseña
    def set_password(self, password):
        self.password_hash = generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role_name):
        """
        Verifica si el usuario tiene un rol específico por su nombre.
        """
        # self.roles es la consulta de SQLAlchemy (lazy='dynamic')
        # Filtramos esa consulta para ver si algún rol coincide
        # con el nombre y contamos si existe.
        return self.roles.filter(Rol.nombre == role_name).count() > 0

class Rol(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)
    
    # Relación inversa de Usuario
    usuarios = db.relationship('Usuario', secondary=usuario_roles,
                               back_populates='roles', lazy='dynamic')

class Categoria(db.Model):
    __tablename__ = 'categorias'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)
    ruta_carpeta = db.Column(db.String(100), unique=True, nullable=False) # Ajusta el tamaño si tus rutas son más largas

    # Relación inversa de Usuario
    usuarios = db.relationship('Usuario', secondary=usuario_permisos,
                               back_populates='permisos', lazy='dynamic')
    
    # Relación (Uno a Muchos)
    # Una categoría tiene muchos documentos.
    documentos = db.relationship('Documento', back_populates='categoria', lazy='dynamic')

class Documento(db.Model):
    __tablename__ = 'documentos'
    id = db.Column(db.Integer, primary_key=True)
    nombre_archivo = db.Column(db.String(255), nullable=False)
    ruta_completa = db.Column(db.String(1024), nullable=False) # 1024 es más seguro para rutas largas
    fecha_indexado = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Llave Foránea
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)
    
    # Relación
    categoria = db.relationship('Categoria', back_populates='documentos')

class LogBusqueda(db.Model):
    __tablename__ = 'log_busquedas'
    id = db.Column(db.Integer, primary_key=True)
    categoria_buscada = db.Column(db.String(100), nullable=False)
    termino_busqueda = db.Column(db.String(255), nullable=False)
    motivo = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Llave Foránea
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)

    # Relación
    usuario = db.relationship('Usuario', back_populates='logs')