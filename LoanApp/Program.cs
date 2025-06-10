using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Concurrent;
using System.Net.Http;
using Microsoft.FSharp.Core;
using LoanRules;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// HTTP client for making requests to mock endpoints
var httpClient = new HttpClient();

// In-memory storage for transaction IDs to ensure uniqueness
var processedTransactionIds = new ConcurrentHashSet<string>();

// Configuration for integrity validation
const string WEBHOOK_SECRET = "webhook-secret-key-2025";

// Webhook endpoint
app.MapPost("/webhook", async (HttpContext context) =>
{
    // Debug: Log the entire request
    string? token = context.Request.Headers["X-Webhook-Token"];
    string? signature = context.Request.Headers["X-Webhook-Signature"];
    app.Logger.LogInformation($"Received request with token: {token}, signature: {signature != null}");

    // Simple auth check - if auth header is incorrect, return 400
    if (token != "meu-token-secreto")
    {
        app.Logger.LogWarning("Authentication failed - returning 400");
        return Results.BadRequest(new { error = "Invalid token" });
    }

    // Read and deserialize the payload
    using var reader = new StreamReader(context.Request.Body);
    var json = await reader.ReadToEndAsync();
    app.Logger.LogInformation($"Received JSON: {json}");

    try
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = true,
            NumberHandling = JsonNumberHandling.AllowReadingFromString
        };

        // Handle empty payload case
        if (string.IsNullOrWhiteSpace(json) || json == "{}")
        {
            app.Logger.LogWarning("Empty payload received - returning 400");
            return Results.BadRequest(new { error = "Empty payload" });
        }

        // Basic payload size validation (before deserialization)
        if (!LoanRules.Integrity.validatePayloadSize(json))
        {
            app.Logger.LogWarning("Payload too large - returning 400");
            return Results.BadRequest(new { error = "Payload too large" });
        }

        var payloadDto = JsonSerializer.Deserialize<WebhookPayloadDto>(json, options);

        if (payloadDto == null)
        {
            app.Logger.LogWarning("Failed to deserialize payload - returning 400");
            return Results.BadRequest(new { error = "Invalid JSON" });
        }

        app.Logger.LogInformation($"Deserialized payload: TransactionId={payloadDto.TransactionId}, Event={payloadDto.Event}, Amount={payloadDto.Amount}");

        // Check if transaction_id is present
        if (string.IsNullOrEmpty(payloadDto.TransactionId))
        {
            app.Logger.LogWarning("Missing transaction_id - returning 400");
            return Results.BadRequest(new { error = "Missing transaction_id" });
        }

        // Check if required fields are present - send cancellation first, then return 400
        if (string.IsNullOrEmpty(payloadDto.Event) ||
            string.IsNullOrEmpty(payloadDto.Currency) ||
            string.IsNullOrEmpty(payloadDto.Timestamp))
        {
            app.Logger.LogWarning("Missing required fields in payload - sending cancellation");
            await SimulateCancellationRequest(payloadDto.TransactionId);
            return Results.BadRequest(new { error = "Missing required fields" });
        }

        // Map to F# record type
        var payload = new Types.WebhookPayload(
            payloadDto.Event,
            payloadDto.TransactionId,
            payloadDto.Amount,
            payloadDto.Currency,
            payloadDto.Timestamp
        );

        // Validate payload using F# pure functions - send cancellation first, then return 400
        var validationResult = Validation.validatePayload(payload);

        if (validationResult.IsError)
        {
            string errorMessage = validationResult.ErrorValue;
            app.Logger.LogWarning($"Validation failed: {errorMessage} - sending cancellation");
            await SimulateCancellationRequest(payload.TransactionId);
            return Results.BadRequest(new { error = errorMessage });
        }

        // NEW: Payload integrity validation
        var signatureOption = string.IsNullOrEmpty(signature) ? null : FSharpOption<string>.Some(signature);
        var integrityResult = LoanRules.Integrity.validatePayloadIntegrity(payload, json, signatureOption, WEBHOOK_SECRET);

        if (integrityResult.IsError)
        {
            string integrityError = integrityResult.ErrorValue;
            app.Logger.LogWarning($"Integrity validation failed: {integrityError} - sending cancellation");
            await SimulateCancellationRequest(payload.TransactionId);
            return Results.BadRequest(new { error = $"Integrity check failed: {integrityError}" });
        }

        // Check for transaction uniqueness - return 400 for duplicates
        if (!processedTransactionIds.Add(payload.TransactionId))
        {
            app.Logger.LogWarning($"Duplicate transaction ID: {payload.TransactionId} - returning 400");
            return Results.BadRequest(new { error = "Duplicate transaction ID" });
        }

        // Process valid transaction - send confirmation and return 200
        app.Logger.LogInformation($"Valid transaction processed: {payload.TransactionId} - sending confirmation");
        await SimulateConfirmationRequest(payload.TransactionId);

        return Results.Ok(new
        {
            message = "Transaction processed successfully",
            transaction_id = payload.TransactionId,
            integrity_validated = signature != null
        });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error processing webhook - returning 400");
        return Results.BadRequest(new { error = ex.Message });
    }
});

// NEW: Endpoint to generate HMAC signature for testing
app.MapPost("/generate-signature", async (HttpContext context) =>
{
    using var reader = new StreamReader(context.Request.Body);
    var payload = await reader.ReadToEndAsync();

    if (string.IsNullOrEmpty(payload))
    {
        return Results.BadRequest(new { error = "Empty payload" });
    }

    var signature = LoanRules.Integrity.computeHmacSignature(payload, WEBHOOK_SECRET);

    return Results.Ok(new
    {
        signature = signature,
        header_format = $"X-Webhook-Signature: {signature}",
        payload_length = payload.Length
    });
});

// Simulate sending confirmation to an external service
async Task SimulateConfirmationRequest(string transactionId)
{
    app.Logger.LogInformation($"Sending confirmation POST for transaction {transactionId}");

    try
    {
        var confirmationData = new
        {
            transaction_id = transactionId
        };

        var content = new StringContent(
            JsonSerializer.Serialize(confirmationData),
            System.Text.Encoding.UTF8,
            "application/json");

        var response = await httpClient.PostAsync("http://localhost:5001/confirmar", content);
        app.Logger.LogInformation($"Confirmation sent - Status: {response.StatusCode}");
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error sending confirmation request");
    }
}

// Simulate sending cancellation to an external service
async Task SimulateCancellationRequest(string transactionId)
{
    app.Logger.LogInformation($"Sending cancellation POST for transaction {transactionId}");

    try
    {
        var cancellationData = new
        {
            transaction_id = transactionId
        };

        var content = new StringContent(
            JsonSerializer.Serialize(cancellationData),
            System.Text.Encoding.UTF8,
            "application/json");

        var response = await httpClient.PostAsync("http://localhost:5001/cancelar", content);
        app.Logger.LogInformation($"Cancellation sent - Status: {response.StatusCode}");
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error sending cancellation request");
    }
}

// Start the server
app.Logger.LogInformation("Webhook server starting up with integrity validation...");
app.Logger.LogInformation($"HMAC secret configured: {WEBHOOK_SECRET[..10]}...");
app.Urls.Add("http://localhost:5000");
app.Run();

// DTO class for JSON deserialization
public class WebhookPayloadDto
{
    [JsonPropertyName("event")]
    public string Event { get; set; } = string.Empty;

    [JsonPropertyName("transaction_id")]
    public string TransactionId { get; set; } = string.Empty;

    [JsonPropertyName("amount")]
    public decimal Amount { get; set; }

    [JsonPropertyName("currency")]
    public string Currency { get; set; } = string.Empty;

    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = string.Empty;
}

// ConcurrentHashSet implementation (not built into .NET)
public class ConcurrentHashSet<T> : ConcurrentDictionary<T, byte> where T : notnull
{
    public bool Add(T item) => TryAdd(item, 0);
}