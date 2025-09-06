# app/routers/usuarios.py
from fastapi import APIRouter, HTTPException
from ..models import UsuarioLogin, UsuarioCadastro
from ..auth import (
    get_usuario,
    gerar_hash,
    autenticar_usuario,
    criar_token,
)
from ..database import usuarios
from ..config import ACCESS_TOKEN_EXPIRE_MINUTES
from datetime import timedelta
from ..viacep import buscar_cep

router = APIRouter(prefix="/usuarios", tags=["Usuários"])


@router.get("/test")
def test():
    return {"mensagem": "OK, tudo certo!"}


@router.post("/registro")
def registrar(usuariox: UsuarioCadastro):
    if get_usuario(usuariox.username):
        raise HTTPException(status_code=400, detail="Usuário já existe")
    hash_senha = gerar_hash(usuariox.password)
    # chamar o viacep
    cep_info = buscar_cep(usuariox.cep)

    usuario_completo = {
        "username": usuariox.username,
        "password": hash_senha,
        "cep": usuariox.cep,
        "numero": usuariox.numero,
        "complemento": usuariox.complemento,
    }

    if cep_info:
        usuario_completo.update(cep_info)

        # adicionar no insert_one os demais dados
        usuarios.insert_one(usuario_completo)
        return {"mensagem": "Usuário registrado com sucesso!"}


@router.post("/login")
def logar(usuario: UsuarioLogin):
    autenticado = autenticar_usuario(usuario.username, usuario.password)

    if not autenticado:
        raise HTTPException(status_code=400, detail="Usuário ou Senha Inválidos")

    access_token = criar_token(
        data={"sub": autenticado["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {
        "token": access_token,
        "expires": timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
