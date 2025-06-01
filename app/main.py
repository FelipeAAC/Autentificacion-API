from datetime import datetime, timedelta, timezone
from typing import Optional, Union
import oracledb
from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
import asyncio
from fastapi.middleware.cors import CORSMiddleware

SECRET_KEY = "your-super-secret-key-replace-this-in-production-with-a-random-one"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600

async def get_conexion():
    try:
        conexion = await asyncio.to_thread(
            oracledb.connect,
            user="prueba_api",
            password="prueba_api",
            dsn="localhost:1521/orcl"
        )
        return conexion
    except oracledb.Error as e:
        print(f"Database connection error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al conectar a la base de datos."
        )

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class ClienteBase(BaseModel):
    correo: str = Field(..., example="usuario@example.com")
    telefono: Optional[str] = Field(None, example="1234567890")

class ClienteCreate(ClienteBase):
    p_nombre: str = Field(..., example="Juan")
    s_nombre: Optional[str] = Field(None, example="Carlos")
    p_apellido: str = Field(..., example="Perez")
    s_apellido: Optional[str] = Field(None, example="Gomez")
    clave: str = Field(..., min_length=6, example="passwordsegura")

class UserInDBBase(BaseModel):
    id: int
    correo: str
    clave_hash: str
    activo: str
    p_nombre: str
    s_nombre: Optional[str] = None
    p_apellido: str
    s_apellido: Optional[str] = None
    telefono: Optional[str] = None
    user_type: str
    rol: Optional[str] = None

    class Config:
        from_attributes = True

class ClienteInDB(UserInDBBase):
    id_cliente: int
    user_type: str = "cliente"
    rol: str = "Cliente"

    def __init__(self, **data):
        super().__init__(id=data.get('id_cliente'), **data)


class EmpleadoInDB(UserInDBBase):
    id_empleado: int
    user_type: str = "empleado"
    id_cargo: Optional[int] = None

    def __init__(self, **data):
        super().__init__(id=data.get('id_empleado'), **data)

class UserPublic(BaseModel):
    id: int
    p_nombre: str
    s_nombre: Optional[str] = None
    p_apellido: str
    s_apellido: Optional[str] = None
    correo: str
    telefono: Optional[str] = None
    activo: str
    rol: str
    user_type: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenResponse(Token):
    user: UserPublic

class TokenData(BaseModel):
    correo: Optional[str] = None
    user_type: Optional[str] = None

app = FastAPI(
    title="API de Autenticación de Clientes y Empleados",
    description="API para el registro y login de clientes y empleados usando FastAPI y JWT con OracleDB.",
    version="1.1.0"
)

origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8001",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def get_user_from_db(db_conn: oracledb.Connection, correo: str) -> Optional[Union[ClienteInDB, EmpleadoInDB]]:
    cursor = None
    try:
        cursor = await asyncio.to_thread(db_conn.cursor)
        await asyncio.to_thread(
            cursor.execute,
            """SELECT id_cliente, p_nombre, s_nombre, p_apellido, s_apellido, 
                      correo, telefono, clave_hash, activo 
               FROM cliente WHERE correo = :correo""",
            correo=correo
        )
        row = await asyncio.to_thread(cursor.fetchone)
        if row:
            user_data = {
                "id_cliente": row[0], "p_nombre": row[1], "s_nombre": row[2],
                "p_apellido": row[3], "s_apellido": row[4], "correo": row[5],
                "telefono": row[6], "clave_hash": row[7], "activo": row[8]
            }
            return ClienteInDB(**user_data)

        await asyncio.to_thread(
            cursor.execute,
            """SELECT e.id_empleado, e.p_nombre, e.s_nombre, e.p_apellido, e.s_apellido,
                      e.correo, e.telefono, e.clave_hash, e.activo, e.id_cargo, c.descripcion as cargo_descripcion
               FROM empleado e
               LEFT JOIN cargo c ON e.id_cargo = c.id_cargo
               WHERE e.correo = :correo""",
            correo=correo
        )
        row = await asyncio.to_thread(cursor.fetchone)
        if row:
            user_data = {
                "id_empleado": row[0], "p_nombre": row[1], "s_nombre": row[2],
                "p_apellido": row[3], "s_apellido": row[4], "correo": row[5],
                "telefono": row[6], "clave_hash": row[7], "activo": row[8],
                "id_cargo": row[9]
            }
            empleado_obj = EmpleadoInDB(**user_data)
            
            cargo_desc = (row[10] or "").lower()
            if "admin" in cargo_desc:
                empleado_obj.rol = "Administrador"
            elif "bodeguero" in cargo_desc:
                empleado_obj.rol = "Bodeguero"
            elif "vendedor" in cargo_desc:
                empleado_obj.rol = "Vendedor"
            elif "cajero" in cargo_desc:
                empleado_obj.rol = "Cajero"
            else:
                empleado_obj.rol = "Empleado" 
            return empleado_obj
            
        return None
    finally:
        if cursor:
            await asyncio.to_thread(cursor.close)

async def get_current_user(token: str = Depends(oauth2_scheme), db_conn: oracledb.Connection = Depends(get_conexion)) -> Union[ClienteInDB, EmpleadoInDB]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        correo: Optional[str] = payload.get("sub")
        user_type: Optional[str] = payload.get("user_type")

        if correo is None or user_type is None:
            raise credentials_exception
        
        token_data = TokenData(correo=correo, user_type=user_type)
        
        user = await get_user_from_db(db_conn, token_data.correo)

        if user is None or user.user_type != token_data.user_type:
            raise credentials_exception
        if user.activo == 'N':
             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Usuario inactivo")

        return user
    except JWTError:
        raise credentials_exception
    except oracledb.Error as e:
        print(f"Database error in get_current_user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de base de datos al obtener usuario."
        )

@app.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED, summary="Registrar un nuevo cliente")
async def register_client(client: ClienteCreate, db_conn: oracledb.Connection = Depends(get_conexion)):

    cursor = None
    try:
        cursor = await asyncio.to_thread(db_conn.cursor)

        user_exists = await get_user_from_db(db_conn, client.correo)
        if user_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El correo ya está registrado"
            )

        hashed_password = get_password_hash(client.clave)

        sql_insert = """
            INSERT INTO cliente ( 
                p_nombre, s_nombre, p_apellido, s_apellido, 
                correo, telefono, clave_hash, activo
            ) VALUES (
                :p_nombre_val, :s_nombre_val, :p_apellido_val, :s_apellido_val, 
                :correo_val, :telefono_val, :clave_hash_val, 'S'
            )
            RETURNING id_cliente INTO :id_cliente_out_bind
        """
        id_cliente_out_var = cursor.var(oracledb.NUMBER)

        await asyncio.to_thread(
            cursor.execute,
            sql_insert,
            p_nombre_val=client.p_nombre,
            s_nombre_val=client.s_nombre,
            p_apellido_val=client.p_apellido,
            s_apellido_val=client.s_apellido,
            correo_val=client.correo,
            telefono_val=client.telefono,
            clave_hash_val=hashed_password,
            id_cliente_out_bind=id_cliente_out_var
        )
        await asyncio.to_thread(db_conn.commit)

        new_id_cliente_tuple = id_cliente_out_var.getvalue()
        if not new_id_cliente_tuple or not new_id_cliente_tuple[0]:
             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No se pudo obtener el ID del cliente generado.")
        new_id_cliente = new_id_cliente_tuple[0]
        
        return UserPublic(
            id=new_id_cliente,
            p_nombre=client.p_nombre,
            s_nombre=client.s_nombre,
            p_apellido=client.p_apellido,
            s_apellido=client.s_apellido,
            correo=client.correo,
            telefono=client.telefono,
            activo='S',
            rol="Cliente",
            user_type="cliente"
        )
    
    except oracledb.Error as e:
        error_obj, = e.args
        if db_conn:
            await asyncio.to_thread(db_conn.rollback)
        print(f"Database error during registration: {error_obj.message.strip()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de base de datos al registrar cliente."
        )
    except HTTPException as http_ex:
        raise http_ex
    except Exception as ex:
        if db_conn:
            await asyncio.to_thread(db_conn.rollback)
        print(f"Unexpected error during registration: {str(ex)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error inesperado en el servidor."
        )
    finally:
        if cursor:
            await asyncio.to_thread(cursor.close)


@app.post("/token", response_model=TokenResponse, summary="Obtener token de acceso para el login")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db_conn: oracledb.Connection = Depends(get_conexion)
):
    user = await get_user_from_db(db_conn, form_data.username)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.activo == 'N':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario inactivo"
        )

    if not verify_password(form_data.password, user.clave_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    access_token = create_access_token(
        data={"sub": user.correo, "user_type": user.user_type, "rol": user.rol}, 
        expires_delta=access_token_expires
    )
    
    user_public_data = UserPublic(
        id=user.id,
        p_nombre=user.p_nombre,
        s_nombre=user.s_nombre,
        p_apellido=user.p_apellido,
        s_apellido=user.s_apellido,
        correo=user.correo,
        telefono=user.telefono,
        activo=user.activo,
        rol=user.rol or ("Cliente" if user.user_type == "cliente" else "Empleado"),
        user_type=user.user_type
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_public_data
    )

@app.get("/users/me", response_model=UserPublic, summary="Obtener información del usuario actual")
async def read_users_me(current_user: Union[ClienteInDB, EmpleadoInDB] = Depends(get_current_user)):
    return UserPublic(
        id=current_user.id,
        p_nombre=current_user.p_nombre,
        s_nombre=current_user.s_nombre,
        p_apellido=current_user.p_apellido,
        s_apellido=current_user.s_apellido,
        correo=current_user.correo,
        telefono=current_user.telefono,
        activo=current_user.activo,
        rol=current_user.rol or ("Cliente" if current_user.user_type == "cliente" else "Empleado"),
        user_type=current_user.user_type
    )

@app.get("/users/by-email", summary="Obtener información básica de usuario (cliente o empleado) por email")
async def get_user_by_email_basic_info(correo: str, db_conn: oracledb.Connection = Depends(get_conexion)):
    user = await get_user_from_db(db_conn, correo)
    if user:
        return {
            "id": user.id,
            "correo": user.correo,
            "activo": user.activo,
            "rol": user.rol or ("Cliente" if user.user_type == "cliente" else "Empleado"),
            "user_type": user.user_type
        }
    raise HTTPException(status_code=404, detail="Usuario no encontrado")
            
@app.post("/activar-cuenta", summary="Activar cuenta y cambiar contraseña para cliente o empleado")
async def activar_cuenta(
    correo: str = Body(..., embed=True),
    nueva_contrasena: str = Body(..., embed=True),
    db_conn: oracledb.Connection = Depends(get_conexion)
):
    cursor = None
    try:
        user_info = await get_user_from_db(db_conn, correo)
        if not user_info:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        hashed_password = get_password_hash(nueva_contrasena)
        cursor = await asyncio.to_thread(db_conn.cursor)

        table_to_update = user_info.user_type

        await asyncio.to_thread(
            cursor.execute,
            f"UPDATE {table_to_update} SET clave_hash = :clave_hash, activo = 'S' WHERE correo = :correo",
            clave_hash=hashed_password,
            correo=correo
        )
        await asyncio.to_thread(db_conn.commit)
        return {"detail": f"Cuenta de {table_to_update} activada y contraseña cambiada"}

    except oracledb.Error as e:
        if db_conn: await asyncio.to_thread(db_conn.rollback)
        print(f"DB error in /activar-cuenta: {e}")
        raise HTTPException(status_code=500, detail="Error de base de datos al activar cuenta.")
    except HTTPException as http_ex:
        raise http_ex
    except Exception as ex:
        if db_conn: await asyncio.to_thread(db_conn.rollback)
        print(f"Unexpected error in /activar-cuenta: {ex}")
        raise HTTPException(status_code=500, detail="Error inesperado al activar cuenta.")
    finally:
        if cursor:
            await asyncio.to_thread(cursor.close)

@app.get("/protected-route", summary="Ejemplo de ruta protegida")
async def read_protected_route(current_user: Union[ClienteInDB, EmpleadoInDB] = Depends(get_current_user)):
    return {
        "message": f"Hola {current_user.p_nombre}! Tienes acceso.",
        "user_id": current_user.id,
        "user_email": current_user.correo,
        "user_type": current_user.user_type,
        "user_rol": current_user.rol
    }