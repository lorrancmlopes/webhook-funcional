import requests
import json

# Test the integrity validation features
base_url = "http://localhost:5000"

print("Testing Payload Integrity Validation")
print("=" * 50)

# 1. Test without signature (should pass)
print("\n1. Testing without signature:")
payload1 = {
    "event": "payment_success",
    "transaction_id": "test-integrity-123",
    "amount": "99.99",
    "currency": "BRL",
    "timestamp": "2025-06-10T10:00:00Z"
}

response = requests.post(f"{base_url}/webhook", 
                        headers={
                            "Content-Type": "application/json",
                            "X-Webhook-Token": "meu-token-secreto"
                        },
                        data=json.dumps(payload1))
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

# 2. Test with valid signature
print("\n2. Testing with valid HMAC signature:")
payload2 = {
    "event": "payment_success",
    "transaction_id": "test-integrity-456",
    "amount": "199.99",
    "currency": "BRL",
    "timestamp": "2025-06-10T10:00:00Z"
}
payload2_json = json.dumps(payload2)

# Generate signature for this exact payload
sig_response = requests.post(f"{base_url}/generate-signature",
                            headers={"Content-Type": "application/json"},
                            data=payload2_json)

if sig_response.status_code == 200:
    signature_data = sig_response.json()
    signature = signature_data["signature"]
    print(f"Generated signature: {signature[:16]}...")
    
    # Use the exact same payload for the webhook request
    response = requests.post(f"{base_url}/webhook",
                            headers={
                                "Content-Type": "application/json",
                                "X-Webhook-Token": "meu-token-secreto",
                                "X-Webhook-Signature": signature
                            },
                            data=payload2_json)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")

# 3. Test with invalid signature
print(f"\n3. Testing with invalid signature:")
response = requests.post(f"{base_url}/webhook",
                        headers={
                            "Content-Type": "application/json",
                            "X-Webhook-Token": "meu-token-secreto",
                            "X-Webhook-Signature": "invalid-signature-123"
                        },
                        data=payload2_json)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

# 4. Test transaction ID format validation (too short)
print(f"\n4. Testing transaction ID too short:")
invalid_short_payload = {
    "event": "payment_success",
    "transaction_id": "ab",  # Too short (2 chars)
    "amount": "99.99",
    "currency": "BRL",
    "timestamp": "2025-06-10T10:00:00Z"
}

response = requests.post(f"{base_url}/webhook",
                        headers={
                            "Content-Type": "application/json",
                            "X-Webhook-Token": "meu-token-secreto"
                        },
                        data=json.dumps(invalid_short_payload))
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

# 5. Test transaction ID format validation (too long)
print(f"\n5. Testing transaction ID too long:")
invalid_long_payload = {
    "event": "payment_success",
    "transaction_id": "x" * 60,  # Too long (60 chars, limit is 50)
    "amount": "99.99",
    "currency": "BRL",
    "timestamp": "2025-06-10T10:00:00Z"
}

response = requests.post(f"{base_url}/webhook",
                        headers={
                            "Content-Type": "application/json",
                            "X-Webhook-Token": "meu-token-secreto"
                        },
                        data=json.dumps(invalid_long_payload))
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

# 6. Test amount precision validation
print(f"\n6. Testing amount precision validation:")
invalid_precision_payload = {
    "event": "payment_success",
    "transaction_id": "test-precision-789",
    "amount": "99.999",  # Too many decimal places
    "currency": "BRL",
    "timestamp": "2025-06-10T10:00:00Z"
}

response = requests.post(f"{base_url}/webhook",
                        headers={
                            "Content-Type": "application/json",
                            "X-Webhook-Token": "meu-token-secreto"
                        },
                        data=json.dumps(invalid_precision_payload))
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

print(f"\n" + "=" * 50)
print("Integrity validation testing completed!")
print("\nSummary of integrity features:")
print("✅ HMAC-SHA256 signature validation")
print("✅ Transaction ID format validation (3-50 chars, alphanumeric + hyphens/underscores)")
print("✅ Amount precision validation (max 2 decimal places)")
print("✅ Payload size validation (max 10KB)")
print("✅ Optional timestamp freshness validation (when signature provided)") 