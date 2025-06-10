# Webhook Test v2 - Enhanced reliability and database constraint handling
import requests
import asyncio
import sys
import json
import time
import uuid
import random
from fastapi import FastAPI, Request
import uvicorn
from threading import Thread

# Criação da aplicação FastAPI
app = FastAPI()

# Variáveis para armazenar confirmações e cancelamentos
confirmations = []
cancellations = []

@app.post("/confirmar")
async def confirmar(req: Request):
    body = await req.json()
    print("✅ Confirmação recebida:", body)
    confirmations.append(body["transaction_id"])
    return {"status": "ok"}

@app.post("/cancelar")
async def cancelar(req: Request):
    body = await req.json()
    print("❌ Cancelamento recebido:", body)
    cancellations.append(body["transaction_id"])
    return {"status": "ok"}

def run_server():
    uvicorn.run(app, host="127.0.0.1", port=5001, log_level="error")

def generate_unique_id(prefix="payment-tx"):
    """Gera IDs únicos usando timestamp, UUID e random para garantir unicidade"""
    timestamp = int(time.time() * 1000)
    uuid_part = str(uuid.uuid4())[:8]
    random_part = random.randint(1000, 9999)
    return f"{prefix}-{timestamp}-{uuid_part}-{random_part}"

async def wait_for_server(max_retries=10, delay=1):
    """Aguarda o servidor local estar pronto com tentativas múltiplas"""
    for attempt in range(max_retries):
        try:
            response = requests.get("http://127.0.0.1:5001", timeout=2)
            print(f"✅ Test server is running on port 5001 (attempt {attempt + 1})")
            return True
        except:
            if attempt < max_retries - 1:
                print(f"⏳ Waiting for test server... (attempt {attempt + 1}/{max_retries})")
                await asyncio.sleep(delay)
            else:
                print("⚠️ Test server may not be fully ready on port 5001")
                return False
    return False

async def load_args():
    base_id = generate_unique_id("payment-tx")
    
    event = sys.argv[1] if len(sys.argv) > 1 else "payment_success"
    transaction_id = sys.argv[2] if len(sys.argv) > 2 else base_id
    amount = sys.argv[3] if len(sys.argv) > 3 else "49.90"
    currency = sys.argv[4] if len(sys.argv) > 4 else "BRL"
    current_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    timestamp = sys.argv[5] if len(sys.argv) > 5 else current_time
    token = sys.argv[6] if len(sys.argv) > 6 else "meu-token-secreto"

    url = "http://localhost:5000/webhook"
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Token": token
    }
    data = {
        "event": event,
        "transaction_id": transaction_id,
        "amount": amount,
        "currency": currency,
        "timestamp": timestamp
    }
    return url, headers, data

async def wait_for_response(transaction_id, response_list, timeout=5):
    """Aguarda uma resposta aparecer na lista com timeout"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if transaction_id in response_list:
            return True
        await asyncio.sleep(0.1)
    return False

async def test_webhook(url, headers, data):
    i = 0
    test_results = []

    print("🚀 Iniciando testes do webhook v2...")
    print(f"📍 Base transaction ID: {data['transaction_id']}")
    
    # Teste 1: fluxo correto
    print("\\n1️⃣ Testando fluxo de pagamento bem-sucedido...")
    response = requests.post(url, headers=headers, data=json.dumps(data))
    confirmed = await wait_for_response(data["transaction_id"], confirmations)
    
    if response.status_code == 200 and confirmed:
        i += 1
        test_results.append("✅ PASS: Successful payment flow")
        print("n✅ Webhook test ok: successful!")
    else:
        test_results.append(f"❌ FAIL: Successful payment flow (status: {response.status_code}, confirmed: {confirmed})")
        print("❌ Webhook test failed: successful!")

    # Teste 2: transação duplicada
    print("\\n2️⃣ Testando detecção de transação duplicada...")
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code != 200:
        i += 1
        test_results.append("✅ PASS: Duplicate transaction detection")
        print("✅ Webhook test ok: transação duplicada!")
    else:
        test_results.append(f"❌ FAIL: Duplicate transaction detection (status: {response.status_code})")
        print("❌ Webhook test failed: transação duplicada!")

    # Teste 3: amount incorreto
    print("\\n3️⃣ Testando validação de amount inválido...")
    test3_data = data.copy()
    test3_data["transaction_id"] = generate_unique_id("test3")
    test3_data["amount"] = "0.00"
    
    response = requests.post(url, headers=headers, data=json.dumps(test3_data))
    cancelled = await wait_for_response(test3_data["transaction_id"], cancellations)
    
    if response.status_code != 200 and cancelled:
        i += 1
        test_results.append("✅ PASS: Invalid amount validation")
        print("✅ Webhook test ok: amount incorreto!")
    else:
        test_results.append(f"❌ FAIL: Invalid amount validation (status: {response.status_code}, cancelled: {cancelled})")
        print("❌ Webhook test failed: amount incorreto!")

    # Teste 4: token inválido
    print("\\n4️⃣ Testando validação de token inválido...")
    test4_headers = headers.copy()
    test4_headers["X-Webhook-Token"] = "invalid-token"
    test4_data = data.copy()
    test4_data["transaction_id"] = generate_unique_id("test4")
    
    response = requests.post(url, headers=test4_headers, data=json.dumps(test4_data))
    if response.status_code != 200:
        i += 1
        test_results.append("✅ PASS: Invalid token validation")
        print("✅ Webhook test ok: Token Invalido!")
    else:
        test_results.append(f"❌ FAIL: Invalid token validation (status: {response.status_code})")
        print("❌ Webhook test failed: Token Invalido!")

    # Teste 5: payload vazio
    print("\\n5️⃣ Testando validação de payload vazio...")
    response = requests.post(url, headers=headers, data=json.dumps({}))
    if response.status_code != 200:
        i += 1
        test_results.append("✅ PASS: Empty payload validation")
        print("✅ Webhook test ok: Payload Invalido!")
    else:
        test_results.append(f"❌ FAIL: Empty payload validation (status: {response.status_code})")
        print("❌ Webhook test failed: Payload Invalido!")

    # Teste 6: campos ausentes
    print("\\n6️⃣ Testando validação de campos obrigatórios ausentes...")
    test6_data = data.copy()
    test6_data["transaction_id"] = generate_unique_id("test6")
    del test6_data["timestamp"]
    
    response = requests.post(url, headers=headers, data=json.dumps(test6_data))
    cancelled = await wait_for_response(test6_data["transaction_id"], cancellations)
    
    if response.status_code != 200 and cancelled:
        i += 1
        test_results.append("✅ PASS: Missing required fields validation")
        print("✅ Webhook test ok: Campos ausentes!")
    else:
        test_results.append(f"❌ FAIL: Missing required fields validation (status: {response.status_code}, cancelled: {cancelled})")
        print("❌ Webhook test failed: Campos ausentes!")

    return i, test_results

if __name__ == "__main__":
    print("🎯 Webhook Test Suite v2 - Enhanced Reliability")
    print("=" * 60)
    
    server_thread = Thread(target=run_server, daemon=True)
    server_thread.start()

    server_ready = asyncio.run(wait_for_server())
    
    if not server_ready:
        print("❌ Falha ao inicializar servidor de teste. Continuando mesmo assim...")

    url, headers, data = asyncio.run(load_args())
    total, test_results = asyncio.run(test_webhook(url, headers, data))

    print("\\n" + "=" * 60)
    print("📊 RESULTADOS DOS TESTES:")
    print("=" * 60)
    
    for result in test_results:
        print(result)
    
    print("\\n" + "=" * 60)
    print(f"✅ RESUMO: {total}/6 testes aprovados")
    print(f"📈 Taxa de sucesso: {(total/6)*100:.1f}%")
    print("=" * 60)
    
    print(f"\\n📋 Confirmações recebidas: {confirmations}")
    print(f"📋 Cancelamentos recebidos: {cancellations}")
    
    if total == 6:
        print("\\n🎉 TODOS OS TESTES APROVADOS! Webhook funcionando perfeitamente.")
    else:
        print(f"\\n⚠️ {6-total} teste(s) falharam. Verifique os logs do webhook para mais detalhes.")