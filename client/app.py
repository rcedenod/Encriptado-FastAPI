from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import io

app = FastAPI(title="Encrypt para server")
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/", response_class=FileResponse) #se usa FileResponse para servir index.html
async def getForm():
    return FileResponse("index.html")

@app.post("/encrypt/")
async def encryptFile(file: UploadFile):
    try:
        data = await file.read() #obtengo los bytes del archivo
        with open("certificate.pem", "rb") as f: #abro el certificando con lectura en binario rb
            certificateData = f.read() #leo los bytes del certificado
            certificate = x509.load_pem_x509_certificate(certificateData) #la clase x509 parsea y retorna un objeto Certificate
            publicKey = certificate.public_key() #extrae la llave publica del certificado retorna objeto RSAPublicKey

        fernetKey = Fernet.generate_key() #genera una llave que utiliza la libreria Fernet para encriptar
        f = Fernet(fernetKey) #crea un objeto Fernet con los metodos encrypt y decrypt
        encryptedFileContent = f.encrypt(data) #se encriptan los bits del archivo (encriptado simetrico)

        #el metodo encrypt de RSAPublicKey utiliza encriptado asimetrico
        #en este caso lo uso solo para la llave publica proveniente de mi certificado
        encryptedKey = publicKey.encrypt(
            fernetKey, #bytes a cifrar
            #agregar relleno al cifrado asimetrico RSA
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #concatenar la llave publica del certificado con el contenido encriptado del archivo
        #len(encryptedKey).to_bytes(4, "big") me ayudara a desencriptar en el server
        package = len(encryptedKey).to_bytes(4, "big") + encryptedKey + encryptedFileContent
        outFileName = f"encrypted_{file.filename}.fernet"

        #la clase StreamingResponse crea una respuesta HTTP que envia chunks de bytes
        #hacia el server
        return StreamingResponse(
            io.BytesIO(package), #buffer en memoria de donde se van a enviar los bytes al server
            media_type="application/octet-stream", #contenido binario
            headers={"Content-Disposition": f'attachment; filename="{outFileName}"'} #pregunta por la descarga
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))