# app/viacep.py
import requests
from fastapi import HTTPException

def buscar_cep(cep: str):
    url = f"https://viacep.com.br/ws/{cep}/json/"
    response = requests.get(url)

    if response.status_code != 200:
        raise HTTPException(status_code=404, detail="CEP não encontrado!")

    dados = response.json()

    if "erro" in dados:
        raise HTTPException(status_code=404, detail="CEP não encontrado!")

    return dados