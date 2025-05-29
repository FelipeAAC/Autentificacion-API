from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Configuración de seguridad
SECRET_KEY = "clave-secreta-ferremas"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Hashing de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Conexión a Oracle (ajusta con tus credenciales y TNS)
DATABASE_URL = "oracle+cx_oracle://prueba:prueba@localhost:1521/prueba"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# Modelo de datos
class ClienteRegistro(BaseModel):
    p_nombre: str
    s_nombre: str | None = None
    p_apellido: str
    s_apellido: str | None = None
    correo: EmailStr
    telefono: str | None = None
    password: str
    confirm_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# App
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilidades de seguridad
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Registro de cliente
@app.post("/auth/registro", status_code=201)
def registro(cliente: ClienteRegistro):
    if cliente.password != cliente.confirm_password:
        raise HTTPException(status_code=400, detail="Las contraseñas no coinciden")

    db = SessionLocal()
    try:
        existe = db.execute(
            text("SELECT 1 FROM cliente WHERE correo = :correo"),
            {"correo": cliente.correo.lower()}
        ).fetchone()

        if existe:
            raise HTTPException(status_code=400, detail="Correo ya registrado")

        hash_clave = hash_password(cliente.password)
        db.execute(
            text("""
                INSERT INTO cliente (id_cliente, p_nombre, s_nombre, p_apellido, s_apellido,
                correo, telefono, clave_hash, activo)
                VALUES (cliente_seq.NEXTVAL, :pn, :sn, :pa, :sa, :correo, :tel, :hash, 'S')
            """),
            {
                "pn": cliente.p_nombre,
                "sn": cliente.s_nombre,
                "pa": cliente.p_apellido,
                "sa": cliente.s_apellido,
                "correo": cliente.correo.lower(),
                "tel": cliente.telefono,
                "hash": hash_clave
            }
        )
        db.commit()
        return {"message": "Registro exitoso"}
    finally:
        db.close()

# Login de cliente
@app.post("/auth/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    try:
        user = db.execute(
            text("SELECT id_cliente, clave_hash FROM cliente WHERE correo = :correo AND activo = 'S'"),
            {"correo": form.username.lower()}
        ).fetchone()

        if not user or not verify_password(form.password, user[1]):
            raise HTTPException(status_code=401, detail="Credenciales inválidas")

        token = create_token({"sub": form.username.lower(), "tipo_usuario": "cliente", "id": user[0]})
        return {"access_token": token, "token_type": "bearer"}
    finally:
        db.close()
