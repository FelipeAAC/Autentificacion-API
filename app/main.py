from fastapi import FastAPI, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, FileResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr, field_validator
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List
import os

# --- Configuración de Seguridad ---
SECRET_KEY = "tu-super-secreto-aqui-cambialo"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 

# --- Contexto de Contraseña ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- OAuth2 Scheme ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# --- Modelos Pydantic ---

class ClientePublic(BaseModel):
    id_cliente: int
    p_nombre: str
    s_nombre: Optional[str] = None
    p_apellido: str
    s_apellido: Optional[str] = None
    correo: EmailStr # Pydantic normaliza el dominio a minúsculas
    telefono: Optional[str] = None
    activo: bool

class ClienteCreate(BaseModel):
    p_nombre: str = Field(..., min_length=1, description="Primer nombre del cliente")
    s_nombre: Optional[str] = Field(None, description="Segundo nombre del cliente")
    p_apellido: str = Field(..., min_length=1, description="Primer apellido del cliente")
    s_apellido: Optional[str] = Field(None, description="Segundo apellido del cliente")
    telefono: Optional[str] = Field(None, description="Teléfono del cliente")
    correo: EmailStr = Field(..., description="Correo electrónico del cliente (será el username)")
    password: str = Field(..., min_length=8, description="Contraseña (mínimo 8 caracteres)")
    confirm_password: str = Field(..., description="Confirmación de la contraseña")

    @field_validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values.data and v != values.data['password']:
            raise ValueError('Las contraseñas no coinciden')
        return v

class ClienteInDB(ClientePublic):
    clave_hash: str

class ClienteRegisterResponse(BaseModel):
    message: str
    cliente_info: ClientePublic
    store_url: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class StoreCategory(BaseModel):
    id: int
    name: str
    product_count: int

class StoreProduct(BaseModel):
    id: int
    name: str
    price: str 

class StorePageData(BaseModel):
    page_title: str
    welcome_message: str
    categories: List[StoreCategory]
    featured_products: List[StoreProduct]


# --- Simulación de Base de Datos ---
fake_clientes_db: Dict[str, ClienteInDB] = {} 
next_cliente_id = 1

# --- Funciones de Utilidad de Seguridad ---

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

# --- Funciones de "Base de Datos" (Simuladas) ---

def get_cliente_by_correo(correo: str) -> Optional[ClienteInDB]:
    # Siempre buscar usando el correo en minúsculas para consistencia
    return fake_clientes_db.get(correo.lower())

def db_create_cliente(cliente_data: ClienteCreate) -> ClienteInDB:
    global next_cliente_id
    # Usar correo en minúsculas para la clave del diccionario y para la verificación de existencia
    normalized_correo = str(cliente_data.correo).lower()

    if get_cliente_by_correo(normalized_correo): # La función get_cliente_by_correo ya usa lower()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El correo electrónico ya está registrado.")

    hashed_password = get_password_hash(cliente_data.password)
    
    db_cliente = ClienteInDB(
        id_cliente=next_cliente_id,
        p_nombre=cliente_data.p_nombre,
        s_nombre=cliente_data.s_nombre,
        p_apellido=cliente_data.p_apellido,
        s_apellido=cliente_data.s_apellido,
        correo=cliente_data.correo, # Guardamos el EmailStr original (Pydantic ya normalizó el dominio)
        telefono=cliente_data.telefono,
        clave_hash=hashed_password,
        activo=True
    )
    fake_clientes_db[normalized_correo] = db_cliente # Usar correo normalizado como clave
    next_cliente_id += 1
    return db_cliente

def db_delete_cliente(correo: str) -> bool:
    normalized_correo = correo.lower() # Asegurar que se usa minúsculas para la clave de eliminación
    if normalized_correo in fake_clientes_db:
        del fake_clientes_db[normalized_correo]
        return True
    return False

# --- Dependencia para obtener el usuario actual ---

async def get_current_active_cliente(token: str = Depends(oauth2_scheme)) -> ClienteInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales o token expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # El 'sub' ya debería estar en minúsculas si se guardó así durante el login
        username: Optional[str] = payload.get("sub") 
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    # get_cliente_by_correo internamente usará minúsculas para la búsqueda
    cliente = get_cliente_by_correo(username) 
    if cliente is None:
        raise credentials_exception
    if not cliente.activo:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cuenta de cliente inactiva.")
    return cliente


# --- Inicialización de la App FastAPI ---
app = FastAPI(title="API Ferretería - Autenticación y Tienda")


# --- Endpoints ---

@app.post("/auth/register", response_model=ClienteRegisterResponse, status_code=status.HTTP_201_CREATED, tags=["Autenticación"])
async def register_cliente(cliente_in: ClienteCreate):
    created_cliente_db = db_create_cliente(cliente_in)
    
    cliente_public_info = ClientePublic(
        id_cliente=created_cliente_db.id_cliente,
        p_nombre=created_cliente_db.p_nombre,
        s_nombre=created_cliente_db.s_nombre,
        p_apellido=created_cliente_db.p_apellido,
        s_apellido=created_cliente_db.s_apellido,
        correo=created_cliente_db.correo, # Se devuelve el EmailStr original
        telefono=created_cliente_db.telefono,
        activo=created_cliente_db.activo
    )
    return ClienteRegisterResponse(
        message="Cliente registrado exitosamente. Ahora puedes iniciar sesión.",
        cliente_info=cliente_public_info,
    )


@app.post("/auth/token", response_model=Token, tags=["Autenticación"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # get_cliente_by_correo usará minúsculas para la búsqueda
    cliente = get_cliente_by_correo(form_data.username) 
    
    if not cliente or not verify_password(form_data.password, cliente.clave_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not cliente.activo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La cuenta está inactiva",
        )
        
    access_token_expires = timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    # Guardar el correo en minúsculas en el 'sub' del token para consistencia
    access_token = create_access_token(
        data={"sub": str(cliente.correo).lower()}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=ClientePublic, tags=["Usuarios"])
async def read_users_me(current_cliente: ClienteInDB = Depends(get_current_active_cliente)):
    return current_cliente

@app.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT, tags=["Usuarios"])
async def delete_user_me(current_cliente: ClienteInDB = Depends(get_current_active_cliente)):
    # El correo en current_cliente.correo es EmailStr, convertir a str y luego a minúsculas para la eliminación
    deleted = db_delete_cliente(str(current_cliente.correo))
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado para eliminar, o ya fue eliminado.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/store", response_model=StorePageData, tags=["Tienda"])
async def get_store_page(current_cliente: ClienteInDB = Depends(get_current_active_cliente)):
    store_data = StorePageData(
        page_title="¡Bienvenido a Ferretería Online!",
        welcome_message=f"Hola, {current_cliente.p_nombre}! Explora nuestras ofertas.",
        categories=[
            StoreCategory(id=1, name="Herramientas Manuales", product_count=120),
            StoreCategory(id=2, name="Herramientas Eléctricas", product_count=75),
            StoreCategory(id=3, name="Materiales de Construcción", product_count=300),
            StoreCategory(id=4, name="Pinturas y Acabados", product_count=90),
        ],
        featured_products=[
            StoreProduct(id=101, name="Martillo de Carpintero Pro", price="12.500 CLP"),
            StoreProduct(id=102, name="Juego de Destornilladores (10 piezas)", price="18.990 CLP"),
            StoreProduct(id=201, name="Taladro Percutor Inalámbrico 18V", price="79.990 CLP"),
            StoreProduct(id=305, name="Saco de Cemento Rápido 25kg", price="5.800 CLP"),
        ]
    )
    return store_data

@app.get("/", response_class=FileResponse, tags=["Frontend Test"])
async def read_index():
    html_file_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(html_file_path):
        return FileResponse(html_file_path)
    else:
        return JSONResponse(
            status_code=404, 
            content={"message": "index.html no encontrado. Asegúrate de que exista en el mismo directorio que main.py."}
        )

