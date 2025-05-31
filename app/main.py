from datetime import datetime, timedelta, timezone
from typing import Optional
import oracledb
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
import asyncio
from fastapi.middleware.cors import CORSMiddleware

SECRET_KEY = "your-super-secret-key-replace-this-in-production-with-a-random-one"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 99999999

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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al conectar a la base de datos: {e}"
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
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
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

class ClienteInDB(ClienteBase):
    id_cliente: int
    p_nombre: str
    s_nombre: Optional[str]
    p_apellido: str
    s_apellido: Optional[str]
    clave_hash: str
    activo: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    correo: Optional[str] = None

app = FastAPI(
    title="API de Autenticación de Clientes",
    description="API para el registro y login de clientes usando FastAPI y JWT con OracleDB.",
    version="1.0.0"
)

origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def get_current_user(token: str = Depends(oauth2_scheme), db_conn: oracledb.Connection = Depends(get_conexion)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    cursor = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        correo: Optional[str] = payload.get("sub")
        if correo is None:
            raise credentials_exception
        token_data = TokenData(correo=correo)
        
        cursor = await asyncio.to_thread(db_conn.cursor)
        await asyncio.to_thread(
            cursor.execute,
            """SELECT id_cliente, p_nombre, s_nombre, p_apellido, s_apellido, 
                      correo, telefono, clave_hash, activo 
               FROM cliente WHERE correo = :correo""",
            correo=token_data.correo
        )
        row = await asyncio.to_thread(cursor.fetchone)
        if row is None:
            raise credentials_exception
        
        user_data = {
            "id_cliente": row[0], "p_nombre": row[1], "s_nombre": row[2],
            "p_apellido": row[3], "s_apellido": row[4], "correo": row[5],
            "telefono": row[6], "clave_hash": row[7], "activo": row[8]
        }
        return ClienteInDB(**user_data)
    except JWTError:
        raise credentials_exception
    except oracledb.Error as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error de base de datos al obtener usuario: {str(e)}"
        )
    finally:
        if cursor:
            await asyncio.to_thread(cursor.close)

@app.post("/register", response_model=ClienteInDB, status_code=status.HTTP_201_CREATED, summary="Registrar un nuevo cliente")
async def register_client(client: ClienteCreate, db_conn: oracledb.Connection = Depends(get_conexion)):
    cursor = None
    try:
        cursor = await asyncio.to_thread(db_conn.cursor)

        await asyncio.to_thread(
            cursor.execute,
            "SELECT COUNT(*) FROM cliente WHERE correo = :correo",
            correo=client.correo
        )
        count_row = await asyncio.to_thread(cursor.fetchone)
        if count_row and count_row[0] > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El correo ya está registrado"
            )

        hashed_password = get_password_hash(client.clave)
        id_cliente_out_var = cursor.var(oracledb.NUMBER)

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
        if not new_id_cliente_tuple:
             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No se pudo obtener el ID del cliente generado.")
        new_id_cliente = new_id_cliente_tuple[0]


        return ClienteInDB(
            id_cliente=new_id_cliente,
            p_nombre=client.p_nombre,
            s_nombre=client.s_nombre,
            p_apellido=client.p_apellido,
            s_apellido=client.s_apellido,
            correo=client.correo,
            telefono=client.telefono,
            clave_hash=hashed_password,
            activo='S'
        )
    except oracledb.Error as e:
        error_obj, = e.args
        if db_conn:
            await asyncio.to_thread(db_conn.rollback)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error de base de datos al registrar cliente: {error_obj.message.strip()}"
        )
    except HTTPException as http_ex:
        raise http_ex
    except Exception as ex:
        if db_conn:
            await asyncio.to_thread(db_conn.rollback)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado en el servidor: {str(ex)}"
        )
    finally:
        if cursor:
            await asyncio.to_thread(cursor.close)

@app.post("/token", response_model=Token, summary="Obtener token de acceso para el login")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db_conn: oracledb.Connection = Depends(get_conexion)):
    cursor = None
    try:
        cursor = await asyncio.to_thread(db_conn.cursor)
        await asyncio.to_thread(
            cursor.execute,
            """SELECT id_cliente, p_nombre, s_nombre, p_apellido, s_apellido, 
                      correo, telefono, clave_hash, activo 
               FROM cliente WHERE correo = :correo""",
            correo=form_data.username
        )
        row = await asyncio.to_thread(cursor.fetchone)

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Correo o contraseña incorrectos"
            )
        
        user_data = {
            "id_cliente": row[0], "p_nombre": row[1], "s_nombre": row[2],
            "p_apellido": row[3], "s_apellido": row[4], "correo": row[5],
            "telefono": row[6], "clave_hash": row[7], "activo": row[8]
        }
        user_in_db = ClienteInDB(**user_data)

        if user_in_db.activo == 'N':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuario inactivo"
            )

        if not verify_password(form_data.password, user_in_db.clave_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Correo o contraseña incorrectos"
            )

        access_token_expires = timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
        access_token = create_access_token(
            data={"sub": user_in_db.correo}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except oracledb.Error as e:
        error_obj, = e.args
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error de base de datos al intentar login: {error_obj.message.strip()}"
        )
    finally:
        if cursor:
            await asyncio.to_thread(cursor.close)

@app.get("/users/me", response_model=ClienteInDB, summary="Obtener información del usuario actual")
async def read_users_me(current_user: ClienteInDB = Depends(get_current_user)):
    return current_user
