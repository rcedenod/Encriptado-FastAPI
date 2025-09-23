import io
import os
import magic  # 👈 librería más robusta
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymPadding
from cryptography.fernet import Fernet, InvalidToken

app = FastAPI(title="Decrypt API con Vista Previa")

app.mount("/static", StaticFiles(directory="."), name="static")
templates = Jinja2Templates(directory=".")

PRIVATE_KEY_PATH = "key.pem"


def unpackPackage(packageBytes: bytes):
    if len(packageBytes) < 4:
        raise ValueError("Paquete demasiado corto")
    offset = 0
    lenKey = int.from_bytes(packageBytes[offset:offset+4], "big")
    offset += 4
    if len(packageBytes) < offset + lenKey:
        raise ValueError("encryptedKey incompleto")
    encryptedKey = packageBytes[offset:offset+lenKey]
    cipherText = packageBytes[offset+lenKey:]
    return encryptedKey, cipherText


def loadPrivateKey(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


@app.get("/", response_class=HTMLResponse)
async def getForm():
    return templates.TemplateResponse("index.html", {"request": {}})


@app.post("/decrypt/", response_class=HTMLResponse)
async def decryptFile(request: Request, file: UploadFile = File(...)):
    try:
        package = await file.read()
        encryptedKey, cipherText = unpackPackage(package)

        privateKey = loadPrivateKey(PRIVATE_KEY_PATH)
        fernetKey = privateKey.decrypt(
            encryptedKey,
            asymPadding.OAEP(
                mgf=asymPadding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        f = Fernet(fernetKey)
        plainText = f.decrypt(cipherText)

        outFileName = file.filename.replace("encrypted_", "decrypted_")

        # 👇 Detectar tipo MIME real con magic
        mimeType = magic.from_buffer(plainText, mime=True)

        token = os.urandom(8).hex()
        if not hasattr(app.state, "tempStore"):
            app.state.tempStore = {}

        app.state.tempStore[token] = (plainText, outFileName, mimeType)

        return templates.TemplateResponse("preview.html", {
            "request": request,
            "filename": outFileName,
            "token": token,
            "mime_type": mimeType  # 👈 usar snake_case en Jinja
        })

    except InvalidToken:
        raise HTTPException(status_code=400, detail="Clave incorrecta o token corrupto")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/view/{token}")
async def viewFile(token: str):
    store = getattr(app.state, "tempStore", {})
    entry = store.get(token)
    if not entry:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    data, outFileName, mimeType = entry
    return StreamingResponse(
        io.BytesIO(data),
        media_type=mimeType,
        headers={"Content-Disposition": f'inline; filename="{outFileName}"'}
    )
