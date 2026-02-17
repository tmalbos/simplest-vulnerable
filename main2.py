# main2.py
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/{user_input}", response_class=HTMLResponse)
async def read_user_input(user_input: str):
    # Esta línea introduce una vulnerabilidad XSS porque el input del usuario se
    # devuelve directamente en la respuesta sin ninguna sanitización o escape.
    # Un atacante podría ingresar un script como parte de user_input.
    return f"<html><body><h1>Your input was: {user_input}</h1></body></html>"
