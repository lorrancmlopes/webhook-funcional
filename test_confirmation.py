import requests
import json
import time
import datetime

# Test the enhanced confirmation system
base_url = "http://localhost:5000"

print("Testing Enhanced Confirmation System")
print("=" * 70)

# 1. Submit a valid transaction to test confirmation system
print("\n1. Submitting valid transaction to test confirmation system:")
valid_payload = {
    "event": "payment_success",
    "transaction_id": "confirm-test-001",
    "amount": "75.50",
    "currency": "BRL",
    "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
}

headers = {
    "Content-Type": "application/json",
    "X-Webhook-Token": "meu-token-secreto"
}

webhook_response = requests.post(f"{base_url}/webhook", 
                                headers=headers, 
                                data=json.dumps(valid_payload))

print(f"Webhook response status: {webhook_response.status_code}")
if webhook_response.status_code == 200:
    response_data = webhook_response.json()
    print(f"Response data: {json.dumps(response_data, indent=2)}")
    
    transaction_id = response_data.get("transaction_id")
    confirmation_status = response_data.get("confirmation_status")
    confirmation_attempts = response_data.get("confirmation_attempts")
    
    print(f"Transaction ID: {transaction_id}")
    print(f"Initial confirmation status: {confirmation_status}")
    print(f"Initial confirmation attempts: {confirmation_attempts}")
else:
    print(f"Error: {webhook_response.text}")

print("\n" + "="*50)

# 2. Check confirmation status
print("\n2. Checking confirmation status:")
if 'transaction_id' in locals():
    time.sleep(1)  # Allow time for confirmation attempt
    
    status_response = requests.get(f"{base_url}/confirmation/{transaction_id}")
    print(f"Status response: {status_response.status_code}")
    
    if status_response.status_code == 200:
        status_data = status_response.json()
        print(f"Confirmation details: {json.dumps(status_data, indent=2)}")
        
        summary = status_data.get("summary", {})
        metrics = status_data.get("metrics", {})
        attempts = status_data.get("attempts", [])
        
        print(f"\nSummary:")
        print(f"  Status: {summary.get('status')}")
        print(f"  Created: {summary.get('created_at')}")
        print(f"  Total attempts: {summary.get('total_attempts')}")
        print(f"  Can retry: {summary.get('can_retry')}")
        print(f"  Is expired: {summary.get('is_expired')}")
        
        print(f"\nMetrics:")
        print(f"  Success rate: {metrics.get('success_rate', 0):.2f}%")
        print(f"  Avg response time: {metrics.get('avg_response_time_ms', 0):.2f}ms")
        print(f"  Time since creation: {metrics.get('time_since_creation_ms', 0):.2f}ms")
        
        print(f"\nAttempts:")
        for attempt in attempts:
            print(f"  Attempt {attempt['attempt_number']}: {'SUCCESS' if attempt['success'] else 'FAILED'}")
            if attempt.get('error_message'):
                print(f"    Error: {attempt['error_message']}")
            if attempt.get('response_time_ms'):
                print(f"    Response time: {attempt['response_time_ms']:.2f}ms")
    else:
        print(f"Error: {status_response.text}")

print("\n" + "="*50)

# 3. Test manual confirmation retry
print("\n3. Testing manual confirmation retry:")
if 'transaction_id' in locals():
    retry_response = requests.post(f"{base_url}/confirmation/{transaction_id}/retry")
    print(f"Retry response: {retry_response.status_code}")
    
    if retry_response.status_code == 200:
        retry_data = retry_response.json()
        print(f"Retry result: {json.dumps(retry_data, indent=2)}")
    else:
        print(f"Retry error: {retry_response.text}")

print("\n" + "="*50)

# 4. Test confirmation statistics
print("\n4. Checking overall confirmation statistics:")
stats_response = requests.get(f"{base_url}/confirmation-stats")
print(f"Stats response: {stats_response.status_code}")

if stats_response.status_code == 200:
    stats_data = stats_response.json()
    print(f"Confirmation statistics: {json.dumps(stats_data, indent=2)}")
    
    print(f"\nOverall Statistics:")
    print(f"  Total confirmations: {stats_data.get('total_confirmations')}")
    print(f"  Confirmed: {stats_data.get('confirmed')}")
    print(f"  Failed: {stats_data.get('failed')}")
    print(f"  Pending: {stats_data.get('pending')}")
    print(f"  Retrying: {stats_data.get('retrying')}")
    print(f"  Overall success rate: {stats_data.get('success_rate', 0):.2f}%")
    print(f"  Average attempts per transaction: {stats_data.get('avg_attempts_per_transaction', 0):.2f}")
    
    config = stats_data.get('configuration', {})
    print(f"\nConfiguration:")
    print(f"  Max retries: {config.get('max_retries')}")
    print(f"  Retry interval: {config.get('retry_interval_seconds')}s")
    print(f"  Confirmation endpoint: {config.get('confirmation_endpoint')}")
else:
    print(f"Error: {stats_response.text}")

print("\n" + "="*50)

# 5. List all confirmations
print("\n5. Listing all confirmations:")
list_response = requests.get(f"{base_url}/confirmations")
print(f"List response: {list_response.status_code}")

if list_response.status_code == 200:
    list_data = list_response.json()
    total = list_data.get('total_confirmations', 0)
    confirmations = list_data.get('confirmations', [])
    
    print(f"Total confirmations: {total}")
    print(f"Confirmations list:")
    
    for i, confirmation in enumerate(confirmations[:5]):  # Show first 5
        print(f"  {i+1}. {confirmation.get('transaction_id')} - {confirmation.get('status')}")
        print(f"     Created: {confirmation.get('created_at')}")
        print(f"     Total attempts: {confirmation.get('total_attempts')}")
else:
    print(f"Error: {list_response.text}")

print("\n" + "="*50)

# 6. Test multiple transactions for better statistics
print("\n6. Testing multiple transactions for statistics:")
for i in range(3):
    test_payload = {
        "event": "payment_success",
        "transaction_id": f"confirm-test-{i+2:03d}",
        "amount": f"{50.00 + i * 25:.2f}",
        "currency": "BRL",
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    
    response = requests.post(f"{base_url}/webhook", 
                           headers=headers, 
                           data=json.dumps(test_payload))
    
    print(f"Transaction {i+2}: {response.status_code} - {test_payload['transaction_id']}")
    if response.status_code == 200:
        data = response.json()
        print(f"  Confirmation status: {data.get('confirmation_status')}")

print("\n" + "="*50)

# 7. Final statistics after multiple transactions
print("\n7. Final confirmation statistics:")
time.sleep(2)  # Allow time for all confirmations to process

final_stats_response = requests.get(f"{base_url}/confirmation-stats")
if final_stats_response.status_code == 200:
    final_stats = final_stats_response.json()
    
    print(f"Final Statistics:")
    print(f"  Total confirmations: {final_stats.get('total_confirmations')}")
    print(f"  Success rate: {final_stats.get('success_rate', 0):.2f}%")
    print(f"  Total attempts: {final_stats.get('total_attempts')}")
    print(f"  Average attempts per transaction: {final_stats.get('avg_attempts_per_transaction', 0):.2f}")
    
    # Check status distribution
    confirmed = final_stats.get('confirmed', 0)
    failed = final_stats.get('failed', 0)
    pending = final_stats.get('pending', 0)
    retrying = final_stats.get('retrying', 0)
    
    print(f"\nStatus Distribution:")
    print(f"  Confirmed: {confirmed}")
    print(f"  Failed: {failed}")
    print(f"  Pending: {pending}")
    print(f"  Retrying: {retrying}")

print("\n" + "="*70)
print("Enhanced Confirmation System Test Complete!")
print("="*70) 