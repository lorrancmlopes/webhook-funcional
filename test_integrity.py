import requests
import json

# Test the integrity validation features
base_url = "http://localhost:5000"

# Test payload
payload = {
    "event": "payment_success",
    "transaction_id": "test-integrity-123",
    "amount": "99.99",
    "currency": "BRL",
    "timestamp": "2025-06-10T10:00:00Z"
}

payload_json = json.dumps(payload)
print("Testing Payload Integrity Validation")
print("=" * 50)

# 1. Test without signature (should pass)
print("\n1. Testing without signature:")
response = requests.post(f"{base_url}/webhook", 
                        headers={
                            "Content-Type": "application/json",
                            "X-Webhook-Token": "meu-token-secreto"
                        },
                        data=payload_json)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

# 2. Generate HMAC signature
print("\n2. Generating HMAC signature:")
sig_response = requests.post(f"{base_url}/generate-signature",
                            headers={"Content-Type": "application/json"},
                            data=payload_json)
print(f"Signature response: {sig_response.text}")

if sig_response.status_code == 200:
    signature_data = sig_response.json()
    signature = signature_data["signature"]
    
    # 3. Test with valid signature
    print(f"\n3. Testing with valid signature: {signature[:16]}...")
    payload["transaction_id"] = "test-integrity-456"  # Change ID to avoid duplicate
    payload_json = json.dumps(payload)
    
    response = requests.post(f"{base_url}/webhook",
                            headers={
                                "Content-Type": "application/json",
                                "X-Webhook-Token": "meu-token-secreto",
                                "X-Webhook-Signature": signature
                            },
                            data=payload_json)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    # 4. Test with invalid signature
    print(f"\n4. Testing with invalid signature:")
    response = requests.post(f"{base_url}/webhook",
                            headers={
                                "Content-Type": "application/json",
                                "X-Webhook-Token": "meu-token-secreto",
                                "X-Webhook-Signature": "invalid-signature-123"
                            },
                            data=payload_json)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")

# 5. Test payload size validation (large payload)
print(f"\n5. Testing payload size validation:")
large_payload = payload.copy()
large_payload["transaction_id"] = "x" * 100  # Very long transaction ID
large_payload_json = json.dumps(large_payload)

response = requests.post(f"{base_url}/webhook",
                        headers={
                            "Content-Type": "application/json",
                            "X-Webhook-Token": "meu-token-secreto"
                        },
                        data=large_payload_json)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

# 6. Test transaction ID format validation
print(f"\n6. Testing transaction ID format validation:")
invalid_id_payload = payload.copy()
invalid_id_payload["transaction_id"] = "ab"  # Too short
invalid_id_payload_json = json.dumps(invalid_id_payload)

response = requests.post(f"{base_url}/webhook",
                        headers={
                            "Content-Type": "application/json",
                            "X-Webhook-Token": "meu-token-secreto"
                        },
                        data=invalid_id_payload_json)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

print(f"\n" + "=" * 50)
print("Integrity validation testing completed!") 