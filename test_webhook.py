# Simulando o envio de um webhook
import requests          # Para fazer requisições HTTP
import asyncio           # Para controle assíncrono
import sys               # Para capturar argumentos de linha de comando
import json              # Para manipular JSON
from fastapi import FastAPI, Request  # Web framework para criar os endpoints locais
import uvicorn           # Para rodar o servidor FastAPI
from threading import Thread  # Para rodar o servidor em paralelo ao teste

# Criação da aplicação FastAPI
app = FastAPI()

# Variáveis para armazenar confirmações e cancelamentos
confirmations = []
cancellations = []

# Endpoint para receber confirmação de transações
@app.post("/confirmar")
async def confirmar(req: Request):
    body = await req.json()
    print("✅ Confirmação recebida:", body)
    confirmations.append(body["transaction_id"])  # Registra a transação confirmada
    return {"status": "ok"}

# Endpoint para receber cancelamento de transações
@app.post("/cancelar")
async def cancelar(req: Request):
    body = await req.json()
    print("❌ Cancelamento recebido:", body)
    cancellations.append(body["transaction_id"])  # Registra a transação cancelada
    return {"status": "ok"}

# Função para rodar o servidor FastAPI numa thread separada
def run_server():
    uvicorn.run(app, host="127.0.0.1", port=5001, log_level="error")

# Carrega argumentos de linha de comando ou usa valores padrão
async def load_args():
    event = sys.argv[1] if len(sys.argv) > 1 else "payment_success"
    transaction_id = sys.argv[2] if len(sys.argv) > 2 else "abc123"
    amount = sys.argv[3] if len(sys.argv) > 3 else "49.90"
    currency = sys.argv[4] if len(sys.argv) > 4 else "BRL"
    timestamp = sys.argv[5] if len(sys.argv) > 5 else "2023-10-01T12:00:00Z"
    token = sys.argv[6] if len(sys.argv) > 6 else "meu-token-secreto"

    url = "http://localhost:5000/webhook"  # URL do webhook a ser testado

    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Token": token  # Token de segurança
    }

    data = {
        "event": event,
        "transaction_id": transaction_id,
        "amount": amount,
        "currency": currency,
        "timestamp": timestamp
    }

    return url, headers, data

# Função principal que executa os testes contra o webhook
async def test_webhook(url, headers, data):
    i = 0  # Contador de testes bem-sucedidos

    # Teste 1: fluxo correto
    response = requests.post(url, headers=headers, data=json.dumps(data))
    await asyncio.sleep(1)  # Aguarda o webhook chamar /confirmar
    if response.status_code == 200 and data["transaction_id"] in confirmations:
        i += 1
        print("1. Webhook test ok: successful!")
    else:
        print("1. Webhook test failed: successful!")

    # Teste 2: transação duplicada (deve falhar se o webhook previne duplicações)
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code != 200:
        i += 1
        print("2. Webhook test ok: transação duplicada!")
    else:
        print("2. Webhook test failed: transação duplicada!")

    # Teste 3: amount incorreto e transaction_id alterado
    data["transaction_id"] += "a"  # Altera ID para evitar conflito
    data["amount"] = "0.00"
    response = requests.post(url, headers=headers, data=json.dumps(data))
    await asyncio.sleep(1)
    if response.status_code != 200 and data["transaction_id"] in cancellations:
        i += 1
        print("3. Webhook test ok: amount incorreto!")
    else:
        print("3. Webhook test failed: amount incorreto!")

    # Teste 4: token inválido
    token = headers["X-Webhook-Token"]
    headers["X-Webhook-Token"] = "invalid-token"
    data["transaction_id"] += "b"
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code != 200:
        i += 1
        print("4. Webhook test ok: Token Invalido!")
    else:
        print("4. Webhook test failed: Token Invalido!")

    # Teste 5: payload vazio
    response = requests.post(url, headers=headers, data=json.dumps({}))
    if response.status_code != 200:
        i += 1
        print("5. Webhook test ok: Payload Invalido!")
    else:
        print("5. Webhook test failed: Payload Invalido!")

    # Teste 6: campos ausentes (sem timestamp)
    del data["timestamp"]
    headers["X-Webhook-Token"] = token  # Restaura token correto
    data["transaction_id"] += "c"
    response = requests.post(url, headers=headers, data=json.dumps(data))
    await asyncio.sleep(1)
    if response.status_code != 200 and data["transaction_id"] in cancellations:
        i += 1
        print("6. Webhook test ok: Campos ausentes!")
    else:
        print("6. Webhook test failed: Campos ausentes!")

    return i

# Bloco principal que inicia o servidor local e executa os testes
if __name__ == "__main__":
    # Roda o servidor local de /confirmar e /cancelar em background
    server_thread = Thread(target=run_server, daemon=True)
    server_thread.start()

    # Aguarda o servidor estar pronto
    asyncio.run(asyncio.sleep(1))

    # Carrega argumentos e executa os testes
    url, headers, data = asyncio.run(load_args())
    total = asyncio.run(test_webhook(url, headers, data))

    # Exibe resultado final
    print(f"{total}/6 tests completed.")
    print("Confirmações recebidas:", confirmations)
    print("Cancelamentos recebidos:", cancellations)
