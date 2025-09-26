import io
import os
import magic
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
#from fastapi.templating import Jinja2Templates # Eliminado: La respuesta será binaria, no HTML

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymPadding
from cryptography.fernet import Fernet, InvalidToken

app = FastAPI(title="Decrypt API para Cliente")
app.mount("/static", StaticFiles(directory="."), name="static") # No es necesario si el cliente lo maneja
# templates = Jinja2Templates(directory=".") # Eliminado: Ya no se usa

origins = [
    "http://127.0.0.1:8000",  # El origen de tu aplicación cliente
    "http://localhost:8000",
    # Puedes agregar otros orígenes si tu cliente se ejecuta en otro puerto o dominio
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,              # Lista de orígenes permitidos
    allow_credentials=True,             # Permite cookies y encabezados de autenticación
    allow_methods=["POST"],             # Permite solo el método POST para /decrypt/
    allow_headers=["*"],                # Permite cualquier encabezado en la solicitud
)

PRIVATE_KEY_PATH = "key.pem"


def unpackPackage(packageBytes: bytes):
    # Función para desempaquetar el paquete encriptado
    if len(packageBytes) < 4:
        raise ValueError("Paquete demasiado corto")
    offset = 0
    lenKey = int.from_bytes(packageBytes[offset:offset+4], "big") #lee el tamanio en bytes de la llave encriptada
    offset += 4
    if len(packageBytes) < offset + lenKey:
        raise ValueError("encryptedKey incompleto")
    encryptedKey = packageBytes[offset:offset+lenKey] #lee la llave encriptada segun el tamanio en lenKey
    encryptedFileContent = packageBytes[offset+lenKey:] #lee lo que sobra, que es el contenido del archivo cifrado
    return encryptedKey, encryptedFileContent


def loadPrivateKey(path: str):
    # Función para cargar la clave privada
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None) #carga la llave privada en un objeto de tipo PrivateKeyTypes


# Se elimina la ruta getForm ya que este servidor solo gestionará la desencriptación.
# @app.get("/", response_class=HTMLResponse)
# async def getForm():
#     return templates.TemplateResponse("index.html", {"request": {}})


@app.post("/decrypt/")
async def decryptFile(file: UploadFile = File(...)):
    # Modificado: La respuesta es un archivo binario para que el cliente pueda previsualizarlo.
    if not file:
        raise HTTPException(status_code=400, detail="No se recibió archivo")
    try:
        package = await file.read() #leo el archivo encriptado
        encryptedKey, encryptedFileContent = unpackPackage(package) #obtengo la llave encriptada y el contendo del archivo cifrado

        privateKey = loadPrivateKey(PRIVATE_KEY_PATH) #obtengo el objeto PrivateKeyTypes
        fernetKey = privateKey.decrypt(
            encryptedKey,
            asymPadding.OAEP(
                mgf=asymPadding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ) #desencripto la llave primero con la llave privada del certificado para poder desencriptar el contenido del archivo

        f = Fernet(fernetKey) #obtengo un objeto Fernet con la llave ya desencriptada
        plainText = f.decrypt(encryptedFileContent) #desencripto el contenido del archivo con el objeto

        # Ajuste en el nombre del archivo para la descarga
        outFileName = file.filename.replace("encrypted_", "decrypted_").replace(".fernet", "")
        mimeType = magic.from_buffer(plainText, mime=True) #detecto que tipo de archivo es

        # La respuesta ahora es el archivo desencriptado en bytes
        return StreamingResponse(
            io.BytesIO(plainText), # Buffer en memoria del contenido desencriptado
            media_type=mimeType, # El cliente usa este encabezado para la vista previa
            headers={"Content-Disposition": f'inline; filename="{outFileName}"'} # El cliente obtiene el nombre del archivo de aquí
        )

    except InvalidToken:
        raise HTTPException(status_code=400, detail="Clave incorrecta o token corrupto")

    except Exception as e:
        # Se incluye el error original para facilitar la depuración
        print(f"Error en el servidor: {e}")
        raise HTTPException(status_code=500, detail=f"Error interno del servidor al desencriptar el archivo: {e}")


# Se eliminan las rutas '/view/{token}' y la lógica 'tempStore'.