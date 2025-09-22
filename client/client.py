from fastapi import FastAPI

app = FastAPI()


@app.get("/helloWorld")
async def helloWorld():
    return {"message": "Hello World"}