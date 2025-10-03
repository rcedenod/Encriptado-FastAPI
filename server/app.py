import io
import os
import magic
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymPadding
from cryptography.fernet import Fernet, InvalidToken

app = FastAPI(title="Decrypt para cliente")
app.mount("/static", StaticFiles(directory="."), name="static")

origins = [
    "http://127.0.0.1:8000",
    "http://localhost:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,              
    allow_credentials=True,             
    allow_methods=["POST"],      
    allow_headers=["*"]         
)

PRIVATE_KEY_PATH = "key.pem"


def unpackPackage(packageBytes: bytes):
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
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None) #carga la llave privada en un objeto de tipo PrivateKeyTypes


@app.post("/decrypt/")
async def decryptFile(file: UploadFile = File(...)):
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
        fileBytes = f.decrypt(encryptedFileContent) #desencripto el contenido del archivo con el objeto

        #ajuste en el nombre del archivo para la descarga
        outFileName = file.filename.replace("encrypted_", "decrypted_").replace(".fernet", "")
        mimeType = magic.from_buffer(fileBytes, mime=True) #detecto que tipo de archivo es

        #la respuesta ahora es el archivo desencriptado en bytes
        return StreamingResponse(
            io.BytesIO(fileBytes), #buffer en memoria del contenido desencriptado
            media_type=mimeType, #el cliente usa este encabezado para la vista previa
            headers={"Content-Disposition": f'inline; filename="{outFileName}"'} #el cliente obtiene el nombre del archivo de aquí
        )

    except InvalidToken:
        raise HTTPException(status_code=400, detail="Clave incorrecta o token corrupto")

    except Exception as e:
        print(f"Error en el servidor: {e}")
        raise HTTPException(status_code=500, detail=f"Error interno del servidor al desencriptar el archivo: {e}")