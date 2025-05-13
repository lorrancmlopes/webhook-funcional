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

// Webhook endpoint
app.MapPost("/webhook", async (HttpContext context) =>
{
    // Debug: Log the entire request
    string? token = context.Request.Headers["X-Webhook-Token"];
    app.Logger.LogInformation($"Received request with token: {token}");

    // Simple auth check - if auth header is incorrect, silently ignore
    if (token != "meu-token-secreto")
    {
        app.Logger.LogWarning("Authentication failed - ignoring request");
        return Results.BadRequest(new { error = "Invalid token" }); // Return 400 for invalid token (test 4)
    }

    // Read and deserialize the payload
    using var reader = new StreamReader(context.Request.Body);
    var json = await reader.ReadToEndAsync();
    app.Logger.LogInformation($"Received JSON: {json}");

    try
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            NumberHandling = JsonNumberHandling.AllowReadingFromString
        };

        // Handle empty payload case
        if (string.IsNullOrWhiteSpace(json) || json == "{}")
        {
            app.Logger.LogWarning("Empty payload received");
            return Results.BadRequest(new { error = "Empty payload" }); // Return 400 for empty payload (test 5)
        }

        var payloadDto = JsonSerializer.Deserialize<WebhookPayloadDto>(json, options);

        if (payloadDto == null)
        {
            app.Logger.LogWarning("Failed to deserialize payload");
            return Results.BadRequest(new { error = "Invalid JSON" }); // Return 400 for invalid JSON
        }

        app.Logger.LogInformation($"Deserialized payload: TransactionId={payloadDto.TransactionId}, Event={payloadDto.Event}, Amount={payloadDto.Amount}");

        // Check if required fields are present
        if (string.IsNullOrEmpty(payloadDto.TransactionId))
        {
            app.Logger.LogWarning("Missing transaction_id");
            return Results.BadRequest(new { error = "Missing transaction_id" }); // Return 400 for missing transaction ID
        }

        if (string.IsNullOrEmpty(payloadDto.Event) ||
            string.IsNullOrEmpty(payloadDto.Currency) ||
            string.IsNullOrEmpty(payloadDto.Timestamp))
        {
            app.Logger.LogWarning("Missing required fields in payload");
            await SimulateCancellationRequest(payloadDto.TransactionId);
            return Results.BadRequest(new { error = "Missing required fields" }); // Return 400 for missing fields (test 6)
        }

        // Map to F# record type
        var payload = new Types.WebhookPayload(
            payloadDto.Event,
            payloadDto.TransactionId,
            payloadDto.Amount,
            payloadDto.Currency,
            payloadDto.Timestamp
        );

        // Validate payload using F# pure functions
        var validationResult = Validation.validatePayload(payload);

        // Check if validation result is Error
        if (validationResult.IsError)
        {
            string errorMessage = validationResult.ErrorValue;
            app.Logger.LogWarning($"Validation failed: {errorMessage}");
            await SimulateCancellationRequest(payload.TransactionId);
            return Results.BadRequest(new { error = errorMessage }); // Return 400 for validation errors (test 3)
        }

        // Check for transaction uniqueness
        if (!processedTransactionIds.Add(payload.TransactionId))
        {
            app.Logger.LogWarning($"Duplicate transaction ID: {payload.TransactionId}");
            // According to test, should be rejected with non-200 status for duplicate transactions
            return Results.BadRequest(new { error = "Duplicate transaction ID" });
        }

        // Process valid transaction
        app.Logger.LogInformation($"Valid transaction processed: {payload.TransactionId}");
        await SimulateConfirmationRequest(payload.TransactionId);

        return Results.Ok();
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error processing webhook");
        return Results.BadRequest(new { error = ex.Message }); // Return 400 for exceptions
    }
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
        app.Logger.LogInformation($"Confirmation response: {response.StatusCode}");
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
        app.Logger.LogInformation($"Cancellation response: {response.StatusCode}");
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error sending cancellation request");
    }
}

// Start the server
app.Logger.LogInformation("Webhook server starting up...");
app.Urls.Add("http://localhost:5000");
app.Run();

// DTO class for JSON deserialization
public class WebhookPayloadDto
{
    public string Event { get; set; } = string.Empty;
    public string TransactionId { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public string Currency { get; set; } = string.Empty;
    public string Timestamp { get; set; } = string.Empty;
}

// ConcurrentHashSet implementation (not built into .NET)
public class ConcurrentHashSet<T> : ConcurrentDictionary<T, byte> where T : notnull
{
    public bool Add(T item) => TryAdd(item, 0);
}