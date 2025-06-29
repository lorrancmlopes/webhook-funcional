﻿using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Concurrent;
using System.Net.Http;
using Microsoft.FSharp.Core;
using LoanRules;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

var builder = WebApplication.CreateBuilder(args);

// Configure Entity Framework with SQLite
builder.Services.AddDbContext<WebhookDbContext>(options =>
    options.UseSqlite("Data Source=webhook_transactions.db"));

var app = builder.Build();

// Ensure database is created
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<WebhookDbContext>();
    dbContext.Database.EnsureCreated();
}

// HTTP client for making requests to mock endpoints
var httpClient = new HttpClient();

// In-memory storage for transaction IDs to ensure uniqueness
var processedTransactionIds = new ConcurrentHashSet<string>();

// NEW: In-memory storage for used nonces to prevent replay attacks
var usedNonces = new ConcurrentHashSet<string>();

// NEW: In-memory storage for confirmation tracking
var confirmationRecords = new ConcurrentDictionary<string, Types.ConfirmationRecord>();

// Configuration for integrity validation
const string WEBHOOK_SECRET = "webhook-secret-key-2025";

// NEW: Configuration for confirmation system
const int MAX_CONFIRMATION_RETRIES = 3;
var CONFIRMATION_RETRY_INTERVAL = TimeSpan.FromSeconds(30);
const string CONFIRMATION_ENDPOINT = "http://localhost:5001/confirmar";

// NEW: Configuration for authenticity validation
var trustedIPs = new List<string> { "127.0.0.1", "::1", "localhost" }; // For testing
const bool ENABLE_STRICT_TIMING = false; // Set to true for production
const bool ENABLE_AUTHENTICITY_CHECKS = true; // Can be disabled for testing





// Webhook endpoint
app.MapPost("/webhook", async (HttpContext context, WebhookDbContext dbContext) =>
{
    var requestStartTime = DateTime.UtcNow;

    // Extract headers for authenticity checks
    string? token = context.Request.Headers["X-Webhook-Token"];
    string? signature = context.Request.Headers["X-Webhook-Signature"];
    string? nonce = context.Request.Headers["X-Webhook-Nonce"];
    string? requestId = context.Request.Headers["X-Request-ID"];
    string? userAgent = context.Request.Headers["User-Agent"];

    // Get client IP (considering reverse proxies)
    string? clientIP = context.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                      ?? context.Request.Headers["X-Real-IP"].FirstOrDefault()
                      ?? context.Connection.RemoteIpAddress?.ToString();

    app.Logger.LogInformation($"Received request: Token={token != null}, Signature={signature != null}, " +
                             $"Nonce={nonce != null}, IP={clientIP}, RequestID={requestId}");

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

            // Save failed transaction to database
            var failedPayload = new Types.WebhookPayload(
                payloadDto.Event ?? "", payloadDto.TransactionId, payloadDto.Amount,
                payloadDto.Currency ?? "", payloadDto.Timestamp ?? DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            await SaveTransactionToDatabase(dbContext, failedPayload, "Cancelled", "Missing required fields", rawPayload: json);

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

            // Save failed transaction to database
            await SaveTransactionToDatabase(dbContext, payload, "Cancelled", errorMessage, rawPayload: json);

            await SimulateCancellationRequest(payload.TransactionId);
            return Results.BadRequest(new { error = errorMessage });
        }

        // NEW: Data Mismatch Detection
        var mismatches = LoanRules.DataMismatch.detectDataMismatches(payload);
        var mismatchArray = Microsoft.FSharp.Collections.ListModule.ToArray(mismatches);
        var mismatchList = Microsoft.FSharp.Collections.ListModule.OfArray(mismatchArray);

        var (shouldCancel, cancelReason) = LoanRules.DataMismatch.shouldCancelTransaction(mismatchList);
        var auditLog = LoanRules.DataMismatch.createMismatchAuditLog(payload, mismatchList, shouldCancel);

        app.Logger.LogInformation($"DATA_MISMATCH_AUDIT: {auditLog}");

        if (shouldCancel)
        {
            app.Logger.LogWarning($"Data mismatch detected - cancelling transaction: {cancelReason}");

            // Save cancelled transaction to database
            await SaveTransactionToDatabase(dbContext, payload, "Cancelled", cancelReason,
                dataMismatchDetected: true, rawPayload: json);

            await SimulateCancellationRequest(payload.TransactionId);
            return Results.BadRequest(new { error = $"Transaction cancelled: {cancelReason}" });
        }

        // Log warnings for non-critical mismatches
        if (mismatchArray.Length > 0 && !shouldCancel)
        {
            var warningTypes = string.Join(", ", mismatchArray.Select(m => m.MismatchType));
            app.Logger.LogWarning($"Non-critical data mismatches detected for {payload.TransactionId}: {warningTypes}");
        }

        // Payload integrity validation
        var signatureOption = string.IsNullOrEmpty(signature) ? null : FSharpOption<string>.Some(signature);
        var integrityResult = LoanRules.Integrity.validatePayloadIntegrity(payload, json, signatureOption, WEBHOOK_SECRET);

        if (integrityResult.IsError)
        {
            string integrityError = integrityResult.ErrorValue;
            app.Logger.LogWarning($"Integrity validation failed: {integrityError} - sending cancellation");

            // Save failed transaction to database
            await SaveTransactionToDatabase(dbContext, payload, "Cancelled", integrityError, rawPayload: json);

            await SimulateCancellationRequest(payload.TransactionId);
            return Results.BadRequest(new { error = $"Integrity check failed: {integrityError}" });
        }

        // NEW: Transaction Authenticity Validation
        if (ENABLE_AUTHENTICITY_CHECKS)
        {
            // Create authenticated payload with metadata
            var authPayload = new Types.AuthenticatedPayload(
                payload,
                string.IsNullOrEmpty(nonce) ? null : FSharpOption<string>.Some(nonce),
                string.IsNullOrEmpty(requestId) ? null : FSharpOption<string>.Some(requestId),
                string.IsNullOrEmpty(clientIP) ? null : FSharpOption<string>.Some(clientIP),
                string.IsNullOrEmpty(userAgent) ? null : FSharpOption<string>.Some(userAgent),
                requestStartTime
            );

            // Get current nonce history for replay protection
            var nonceHistoryArray = usedNonces.Keys.ToArray();
            var nonceHistoryList = Microsoft.FSharp.Collections.ListModule.OfArray(nonceHistoryArray);

            // Create IP whitelist (optional for testing, can be null)
            var ipWhitelistArray = trustedIPs.ToArray();
            var ipWhitelistOption = FSharpOption<string[]>.Some(ipWhitelistArray);
            var ipWhitelistFSharp = Microsoft.FSharp.Collections.ListModule.OfArray(ipWhitelistArray);
            var ipWhitelistOptionFSharp = FSharpOption<Microsoft.FSharp.Collections.FSharpList<string>>.Some(ipWhitelistFSharp);

            // Perform authenticity validation
            var authenticityResult = LoanRules.Authenticity.validateTransactionAuthenticity(
                authPayload,
                nonceHistoryList,
                ipWhitelistOptionFSharp,
                ENABLE_STRICT_TIMING
            );

            // Create audit log entry
            var auditEntry = LoanRules.Authenticity.createAuditLogEntry(authPayload, authenticityResult);
            app.Logger.LogInformation($"AUDIT: {auditEntry}");

            if (authenticityResult.IsError)
            {
                string authError = authenticityResult.ErrorValue;
                app.Logger.LogWarning($"Authenticity validation failed: {authError} - sending cancellation");

                // Save failed transaction to database
                var authRequestFingerprint = !string.IsNullOrEmpty(nonce) && !string.IsNullOrEmpty(requestId)
                    ? LoanRules.Authenticity.generateRequestFingerprint(authPayload) : null;
                await SaveTransactionToDatabase(dbContext, payload, "Cancelled", authError,
                    nonce: nonce, requestId: requestId, clientIp: clientIP, userAgent: userAgent,
                    requestFingerprint: authRequestFingerprint, rawPayload: json);

                await SimulateCancellationRequest(payload.TransactionId);
                return Results.BadRequest(new { error = $"Authenticity check failed: {authError}" });
            }

            // Add nonce to used nonces if provided (replay protection)
            if (!string.IsNullOrEmpty(nonce))
            {
                usedNonces.Add(nonce);
                app.Logger.LogInformation($"Nonce {nonce[..8]}... added to replay protection list");
            }
        }

        // Check for transaction uniqueness in database - return 400 for duplicates
        var existingTransaction = await dbContext.Transactions
            .FirstOrDefaultAsync(t => t.TransactionId == payload.TransactionId);

        if (existingTransaction != null)
        {
            app.Logger.LogWarning($"Duplicate transaction ID: {payload.TransactionId} - returning 400");
            return Results.BadRequest(new { error = "Duplicate transaction ID" });
        }

        // Add to in-memory collection for quick subsequent checks within same session
        processedTransactionIds.Add(payload.TransactionId);

        // Process valid transaction - initialize enhanced confirmation system
        app.Logger.LogInformation($"Valid transaction processed: {payload.TransactionId} - initializing confirmation");

        // Generate request fingerprint for audit
        string? requestFingerprint = null;
        if (ENABLE_AUTHENTICITY_CHECKS && !string.IsNullOrEmpty(nonce) && !string.IsNullOrEmpty(requestId))
        {
            var authPayload = new Types.AuthenticatedPayload(
                payload, FSharpOption<string>.Some(nonce), FSharpOption<string>.Some(requestId),
                string.IsNullOrEmpty(clientIP) ? null : FSharpOption<string>.Some(clientIP),
                string.IsNullOrEmpty(userAgent) ? null : FSharpOption<string>.Some(userAgent),
                requestStartTime);
            requestFingerprint = LoanRules.Authenticity.generateRequestFingerprint(authPayload);
        }

        // Save successful transaction to database
        var savedTransaction = await SaveTransactionToDatabase(dbContext, payload, "Pending",
            integrityValidated: signature != null, authenticityValidated: ENABLE_AUTHENTICITY_CHECKS,
            dataMismatchDetected: mismatchArray.Length > 0,
            nonce: nonce, requestId: requestId, clientIp: clientIP, userAgent: userAgent,
            requestFingerprint: requestFingerprint, rawPayload: json);

        // Create confirmation record using F# function
        var confirmationRecord = LoanRules.Confirmation.createConfirmationRecord(payload, MAX_CONFIRMATION_RETRIES, CONFIRMATION_RETRY_INTERVAL);

        // Store confirmation record for tracking
        confirmationRecords.TryAdd(payload.TransactionId, confirmationRecord);

        // Attempt initial confirmation
        var confirmationResult = await AttemptTransactionConfirmation(payload, confirmationRecord);

        return Results.Ok(new
        {
            message = "Transaction processed successfully",
            transaction_id = payload.TransactionId,
            integrity_validated = signature != null,
            authenticity_validated = ENABLE_AUTHENTICITY_CHECKS,
            nonce_provided = !string.IsNullOrEmpty(nonce),
            request_id = requestId,
            confirmation_status = confirmationResult.Item1.ToString(),
            confirmation_initiated = true,
            confirmation_attempts = confirmationResult.Item2
        });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error processing webhook - returning 400");
        return Results.BadRequest(new { error = ex.Message });
    }
});

// Endpoint to generate HMAC signature for testing
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

// NEW: Endpoint to generate nonce for testing authenticity features
app.MapPost("/generate-nonce", (HttpContext context) =>
{
    var nonce = Guid.NewGuid().ToString();
    var requestId = $"req-{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}-{Random.Shared.Next(1000, 9999)}";

    return Results.Ok(new
    {
        nonce = nonce,
        request_id = requestId,
        timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        usage_example = new
        {
            headers = new
            {
                X_Webhook_Nonce = nonce,
                X_Request_ID = requestId,
                User_Agent = "WebhookClient/1.0"
            }
        }
    });
});

// NEW: Endpoint to get authenticity status and statistics
app.MapGet("/authenticity-status", (HttpContext context) =>
{
    return Results.Ok(new
    {
        authenticity_checks_enabled = ENABLE_AUTHENTICITY_CHECKS,
        strict_timing_enabled = ENABLE_STRICT_TIMING,
        trusted_ips = trustedIPs,
        nonce_cache_size = usedNonces.Count,
        transaction_cache_size = processedTransactionIds.Count,
        features = new
        {
            nonce_replay_protection = true,
            ip_whitelisting = true,
            request_fingerprinting = true,
            strict_timing_validation = ENABLE_STRICT_TIMING,
            audit_logging = true
        }
    });
});

// NEW: Endpoint to clear nonce cache (for testing)
app.MapPost("/clear-nonce-cache", (HttpContext context) =>
{
    var clearedCount = usedNonces.Count;
    usedNonces.Clear();

    app.Logger.LogInformation($"Cleared {clearedCount} nonces from replay protection cache");

    return Results.Ok(new
    {
        message = "Nonce cache cleared",
        cleared_count = clearedCount
    });
});

// NEW: Endpoint to test data mismatch detection
app.MapPost("/test-mismatch", async (HttpContext context) =>
{
    using var reader = new StreamReader(context.Request.Body);
    var json = await reader.ReadToEndAsync();

    if (string.IsNullOrEmpty(json))
    {
        return Results.BadRequest(new { error = "Empty payload" });
    }

    try
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = true,
            NumberHandling = JsonNumberHandling.AllowReadingFromString
        };

        var payloadDto = JsonSerializer.Deserialize<WebhookPayloadDto>(json, options);

        if (payloadDto == null)
        {
            return Results.BadRequest(new { error = "Invalid JSON" });
        }

        var payload = new Types.WebhookPayload(
            payloadDto.Event,
            payloadDto.TransactionId,
            payloadDto.Amount,
            payloadDto.Currency,
            payloadDto.Timestamp
        );

        // Detect mismatches without processing transaction
        var mismatches = LoanRules.DataMismatch.detectDataMismatches(payload);
        var mismatchArray = Microsoft.FSharp.Collections.ListModule.ToArray(mismatches);
        var mismatchList = Microsoft.FSharp.Collections.ListModule.OfArray(mismatchArray);

        var (shouldCancel, cancelReason) = LoanRules.DataMismatch.shouldCancelTransaction(mismatchList);
        var auditLog = LoanRules.DataMismatch.createMismatchAuditLog(payload, mismatchList, shouldCancel);

        return Results.Ok(new
        {
            transaction_id = payload.TransactionId,
            mismatches_detected = mismatchArray.Length,
            should_cancel = shouldCancel,
            cancel_reason = cancelReason,
            audit_log = auditLog,
            mismatch_details = mismatchArray.Select(m => new
            {
                type = m.MismatchType,
                description = m.Description,
                should_cancel = m.ShouldCancel
            }).ToArray()
        });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// Enhanced confirmation system with retry logic and tracking
async Task<(Types.ConfirmationStatus, int)> AttemptTransactionConfirmation(Types.WebhookPayload payload, Types.ConfirmationRecord record)
{
    var stopwatch = System.Diagnostics.Stopwatch.StartNew();

    // Create a new scope to get fresh DbContext instance
    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<WebhookDbContext>();

    // Determine attempt number
    var attemptNumber = record.Attempts.Length + 1;

    try
    {
        app.Logger.LogInformation($"Attempting confirmation #{attemptNumber} for transaction {payload.TransactionId}");

        // Validate confirmation data using F# function
        var validationResult = LoanRules.Confirmation.validateConfirmationData(payload);
        if (validationResult.IsError)
        {
            var errorAttempt = LoanRules.Confirmation.createConfirmationAttempt(attemptNumber, false,
                FSharpOption<string>.Some($"Validation failed: {validationResult.ErrorValue}"), null);
            var updatedRecord = LoanRules.Confirmation.updateConfirmationRecord(record, errorAttempt);
            confirmationRecords.TryUpdate(payload.TransactionId, updatedRecord, record);

            // Update database with failed confirmation
            await UpdateTransactionConfirmationStatus(dbContext, payload.TransactionId, "Failed",
                attemptNumber, confirmationError: validationResult.ErrorValue);

            var auditLog = LoanRules.Confirmation.createConfirmationAuditLog(updatedRecord, FSharpOption<Types.ConfirmationAttempt>.Some(errorAttempt));
            app.Logger.LogWarning($"CONFIRMATION_AUDIT: {auditLog}");

            return (updatedRecord.Status, attemptNumber);
        }

        // Generate confirmation payload
        var confirmationId = Guid.NewGuid().ToString();
        var confirmationPayload = LoanRules.Confirmation.generateConfirmationPayload(payload, confirmationId);

        // Convert F# Map to C# dictionary for serialization
        var payloadDict = new Dictionary<string, object>();
        foreach (var kvp in confirmationPayload)
        {
            payloadDict[kvp.Key] = kvp.Value;
        }

        var content = new StringContent(
            JsonSerializer.Serialize(payloadDict),
            System.Text.Encoding.UTF8,
            "application/json");

        var response = await httpClient.PostAsync(CONFIRMATION_ENDPOINT, content);
        stopwatch.Stop();

        var responseTime = FSharpOption<System.TimeSpan>.Some(stopwatch.Elapsed);
        var responseBody = await response.Content.ReadAsStringAsync();

        // Validate response using F# function
        var (isSuccess, errorMessage) = LoanRules.Confirmation.validateConfirmationResponse((int)response.StatusCode,
            string.IsNullOrEmpty(responseBody) ? null : FSharpOption<string>.Some(responseBody));

        // Create attempt record
        var attempt = LoanRules.Confirmation.createConfirmationAttempt(attemptNumber, isSuccess,
            Microsoft.FSharp.Core.FSharpOption<string>.get_IsSome(errorMessage) ? errorMessage : null, responseTime);

        // Update confirmation record
        var finalRecord = LoanRules.Confirmation.updateConfirmationRecord(record, attempt);
        confirmationRecords.TryUpdate(payload.TransactionId, finalRecord, record);

        // Update database with confirmation status
        var dbStatus = isSuccess ? "Confirmed" : (LoanRules.Confirmation.shouldRetryConfirmation(finalRecord) ? "Retrying" : "Failed");
        var confirmedAt = isSuccess ? DateTime.UtcNow : (DateTime?)null;
        var dbErrorMessage = Microsoft.FSharp.Core.FSharpOption<string>.get_IsSome(errorMessage) ? errorMessage.Value : null;

        await UpdateTransactionConfirmationStatus(dbContext, payload.TransactionId, dbStatus,
            attemptNumber, confirmedAt, dbErrorMessage);

        // Create audit log
        var finalAuditLog = LoanRules.Confirmation.createConfirmationAuditLog(finalRecord, FSharpOption<Types.ConfirmationAttempt>.Some(attempt));
        app.Logger.LogInformation($"CONFIRMATION_AUDIT: {finalAuditLog}");

        // Schedule retry if needed
        if (!isSuccess && LoanRules.Confirmation.shouldRetryConfirmation(finalRecord))
        {
            var nextRetryTime = LoanRules.Confirmation.getNextRetryTime(finalRecord);
            if (Microsoft.FSharp.Core.FSharpOption<System.DateTime>.get_IsSome(nextRetryTime))
            {
                app.Logger.LogInformation($"Scheduling confirmation retry for {payload.TransactionId} at {nextRetryTime.Value}");
                // In a real application, you would schedule this with a background service
                _ = Task.Delay(CONFIRMATION_RETRY_INTERVAL).ContinueWith(async _ =>
                {
                    if (confirmationRecords.TryGetValue(payload.TransactionId, out var currentRecord))
                    {
                        await AttemptTransactionConfirmation(payload, currentRecord);
                    }
                });
            }
        }

        return (finalRecord.Status, attemptNumber);
    }
    catch (Exception ex)
    {
        stopwatch.Stop();
        var responseTime = FSharpOption<System.TimeSpan>.Some(stopwatch.Elapsed);
        var errorAttempt = LoanRules.Confirmation.createConfirmationAttempt(attemptNumber, false,
            FSharpOption<string>.Some(ex.Message), responseTime);

        var errorRecord = LoanRules.Confirmation.updateConfirmationRecord(record, errorAttempt);
        confirmationRecords.TryUpdate(payload.TransactionId, errorRecord, record);

        // Update database with error
        await UpdateTransactionConfirmationStatus(dbContext, payload.TransactionId, "Failed",
            attemptNumber, confirmationError: ex.Message);

        var errorAuditLog = LoanRules.Confirmation.createConfirmationAuditLog(errorRecord, FSharpOption<Types.ConfirmationAttempt>.Some(errorAttempt));
        app.Logger.LogError($"CONFIRMATION_AUDIT: {errorAuditLog}");

        return (errorRecord.Status, attemptNumber);
    }
}

// Legacy confirmation method for cancellations (simplified)
async Task SimulateCancellationRequest(string transactionId)
{
    app.Logger.LogInformation($"Sending cancellation POST for transaction {transactionId}");

    try
    {
        var cancellationData = new
        {
            transaction_id = transactionId,
            status = "cancelled",
            cancelled_at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
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

// NEW: Endpoint to get confirmation status
app.MapGet("/confirmation/{transactionId}", (string transactionId) =>
{
    if (confirmationRecords.TryGetValue(transactionId, out var record))
    {
        var summary = LoanRules.Confirmation.getConfirmationSummary(record);
        var metrics = LoanRules.Confirmation.calculateConfirmationMetrics(record);

        // Convert F# Maps to C# dictionaries for JSON serialization
        var summaryDict = summary.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        var metricsDict = metrics.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

        return Results.Ok(new
        {
            summary = summaryDict,
            metrics = metricsDict,
            attempts = record.Attempts.Select(attempt => new
            {
                attempt_number = attempt.AttemptNumber,
                timestamp = attempt.Timestamp.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                success = attempt.Success,
                error_message = Microsoft.FSharp.Core.FSharpOption<string>.get_IsSome(attempt.ErrorMessage) ? attempt.ErrorMessage.Value : null,
                response_time_ms = Microsoft.FSharp.Core.FSharpOption<System.TimeSpan>.get_IsSome(attempt.ResponseTime) ? (double?)attempt.ResponseTime.Value.TotalMilliseconds : null
            }).ToArray()
        });
    }
    else
    {
        return Results.NotFound(new { error = "Confirmation record not found" });
    }
});

// NEW: Endpoint to manually retry confirmation
app.MapPost("/confirmation/{transactionId}/retry", async (string transactionId) =>
{
    if (confirmationRecords.TryGetValue(transactionId, out var record))
    {
        if (LoanRules.Confirmation.shouldRetryConfirmation(record))
        {
            var (status, attemptNumber) = await AttemptTransactionConfirmation(record.OriginalPayload, record);

            return Results.Ok(new
            {
                message = "Retry attempt completed",
                transaction_id = transactionId,
                status = status.ToString(),
                attempt_number = attemptNumber
            });
        }
        else
        {
            return Results.BadRequest(new { error = "Cannot retry confirmation - max retries reached or already confirmed" });
        }
    }
    else
    {
        return Results.NotFound(new { error = "Confirmation record not found" });
    }
});

// NEW: Endpoint to list all confirmations
app.MapGet("/confirmations", () =>
{
    var confirmations = confirmationRecords.Values.Select(record =>
    {
        var summary = LoanRules.Confirmation.getConfirmationSummary(record);
        return summary.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
    }).ToArray();

    return Results.Ok(new
    {
        total_confirmations = confirmations.Length,
        confirmations = confirmations
    });
});

// NEW: Endpoint to get confirmation statistics
app.MapGet("/confirmation-stats", () =>
{
    var allRecords = confirmationRecords.Values.ToArray();
    var totalConfirmations = allRecords.Length;
    var confirmedCount = allRecords.Count(r => r.Status == Types.ConfirmationStatus.Confirmed);
    var failedCount = allRecords.Count(r => r.Status == Types.ConfirmationStatus.Failed);
    var pendingCount = allRecords.Count(r => r.Status == Types.ConfirmationStatus.Pending);
    var retryingCount = allRecords.Count(r => r.Status == Types.ConfirmationStatus.Retrying);

    var totalAttempts = allRecords.Sum(r => r.Attempts.Length);
    var avgAttemptsPerTransaction = totalConfirmations > 0 ? (double)totalAttempts / totalConfirmations : 0;

    var successfulAttempts = allRecords.SelectMany(r => r.Attempts).Count(a => a.Success);
    var overallSuccessRate = totalAttempts > 0 ? (double)successfulAttempts / totalAttempts * 100 : 0;

    return Results.Ok(new
    {
        total_confirmations = totalConfirmations,
        confirmed = confirmedCount,
        failed = failedCount,
        pending = pendingCount,
        retrying = retryingCount,
        success_rate = Math.Round(overallSuccessRate, 2),
        avg_attempts_per_transaction = Math.Round(avgAttemptsPerTransaction, 2),
        total_attempts = totalAttempts,
        configuration = new
        {
            max_retries = MAX_CONFIRMATION_RETRIES,
            retry_interval_seconds = CONFIRMATION_RETRY_INTERVAL.TotalSeconds,
            confirmation_endpoint = CONFIRMATION_ENDPOINT
        }
    });
});

// NEW: Database Query Endpoints

// Get all transactions with optional filtering
app.MapGet("/transactions", async (WebhookDbContext dbContext,
    string? status = null,
    string? @event = null,
    int page = 1,
    int pageSize = 50) =>
{
    var query = dbContext.Transactions.AsQueryable();

    if (!string.IsNullOrEmpty(status))
        query = query.Where(t => t.Status == status);

    if (!string.IsNullOrEmpty(@event))
        query = query.Where(t => t.Event == @event);

    var totalCount = await query.CountAsync();
    var transactions = await query
        .OrderByDescending(t => t.ProcessedAt)
        .Skip((page - 1) * pageSize)
        .Take(pageSize)
        .Select(t => new
        {
            id = t.Id,
            transaction_id = t.TransactionId,
            @event = t.Event,
            amount = t.Amount,
            currency = t.Currency,
            timestamp = t.Timestamp.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            processed_at = t.ProcessedAt.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            status = t.Status,
            error_message = t.ErrorMessage,
            integrity_validated = t.IntegrityValidated,
            authenticity_validated = t.AuthenticityValidated,
            data_mismatch_detected = t.DataMismatchDetected,
            confirmation_attempts = t.ConfirmationAttempts,
            confirmed_at = t.ConfirmedAt != null ? t.ConfirmedAt.Value.ToString("yyyy-MM-ddTHH:mm:ssZ") : null,
            nonce = t.Nonce,
            request_id = t.RequestId,
            client_ip = t.ClientIp,
            user_agent = t.UserAgent,
            request_fingerprint = t.RequestFingerprint
        })
        .ToArrayAsync();

    return Results.Ok(new
    {
        total_count = totalCount,
        page = page,
        page_size = pageSize,
        total_pages = (int)Math.Ceiling((double)totalCount / pageSize),
        transactions = transactions
    });
});

// Get specific transaction by ID
app.MapGet("/transactions/{transactionId}", async (WebhookDbContext dbContext, string transactionId) =>
{
    var transaction = await dbContext.Transactions
        .FirstOrDefaultAsync(t => t.TransactionId == transactionId);

    if (transaction == null)
    {
        return Results.NotFound(new { error = "Transaction not found" });
    }

    return Results.Ok(new
    {
        id = transaction.Id,
        transaction_id = transaction.TransactionId,
        @event = transaction.Event,
        amount = transaction.Amount,
        currency = transaction.Currency,
        timestamp = transaction.Timestamp.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        processed_at = transaction.ProcessedAt.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        status = transaction.Status,
        error_message = transaction.ErrorMessage,
        integrity_validated = transaction.IntegrityValidated,
        authenticity_validated = transaction.AuthenticityValidated,
        data_mismatch_detected = transaction.DataMismatchDetected,
        confirmation_attempts = transaction.ConfirmationAttempts,
        confirmed_at = transaction.ConfirmedAt?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        confirmation_error = transaction.ConfirmationError,
        nonce = transaction.Nonce,
        request_id = transaction.RequestId,
        client_ip = transaction.ClientIp,
        user_agent = transaction.UserAgent,
        request_fingerprint = transaction.RequestFingerprint,
        raw_payload = transaction.RawPayload
    });
});

// Get transaction statistics
app.MapGet("/transaction-stats", async (WebhookDbContext dbContext) =>
{
    var totalTransactions = await dbContext.Transactions.CountAsync();
    var confirmedCount = await dbContext.Transactions.CountAsync(t => t.Status == "Confirmed");
    var cancelledCount = await dbContext.Transactions.CountAsync(t => t.Status == "Cancelled");
    var failedCount = await dbContext.Transactions.CountAsync(t => t.Status == "Failed");
    var pendingCount = await dbContext.Transactions.CountAsync(t => t.Status == "Pending");
    var retryingCount = await dbContext.Transactions.CountAsync(t => t.Status == "Retrying");

    var integrityValidatedCount = await dbContext.Transactions.CountAsync(t => t.IntegrityValidated);
    var authenticityValidatedCount = await dbContext.Transactions.CountAsync(t => t.AuthenticityValidated);
    var dataMismatchDetectedCount = await dbContext.Transactions.CountAsync(t => t.DataMismatchDetected);

    var avgConfirmationAttempts = await dbContext.Transactions
        .Where(t => t.ConfirmationAttempts > 0)
        .AverageAsync(t => (double)t.ConfirmationAttempts);

    var recentTransactions = await dbContext.Transactions
        .OrderByDescending(t => t.ProcessedAt)
        .Take(5)
        .Select(t => new { t.TransactionId, t.Status, t.ProcessedAt })
        .ToArrayAsync();

    return Results.Ok(new
    {
        total_transactions = totalTransactions,
        status_breakdown = new
        {
            confirmed = confirmedCount,
            cancelled = cancelledCount,
            failed = failedCount,
            pending = pendingCount,
            retrying = retryingCount
        },
        security_stats = new
        {
            integrity_validated = integrityValidatedCount,
            authenticity_validated = authenticityValidatedCount,
            data_mismatch_detected = dataMismatchDetectedCount
        },
        confirmation_stats = new
        {
            avg_attempts = Math.Round(avgConfirmationAttempts, 2),
            success_rate = totalTransactions > 0 ? Math.Round((double)confirmedCount / totalTransactions * 100, 2) : 0
        },
        recent_transactions = recentTransactions.Select(t => new
        {
            transaction_id = t.TransactionId,
            status = t.Status,
            processed_at = t.ProcessedAt.ToString("yyyy-MM-ddTHH:mm:ssZ")
        })
    });
});

// Database Helper Methods
async Task<TransactionRecord> SaveTransactionToDatabase(
    WebhookDbContext dbContext,
    Types.WebhookPayload payload,
    string status,
    string? errorMessage = null,
    bool integrityValidated = false,
    bool authenticityValidated = false,
    bool dataMismatchDetected = false,
    string? nonce = null,
    string? requestId = null,
    string? clientIp = null,
    string? userAgent = null,
    string? requestFingerprint = null,
    string? rawPayload = null)
{
    // Check if transaction already exists to prevent UNIQUE constraint violations
    var existingTransaction = await dbContext.Transactions
        .FirstOrDefaultAsync(t => t.TransactionId == payload.TransactionId);

    if (existingTransaction != null)
    {
        app.Logger.LogWarning($"DATABASE: Transaction {payload.TransactionId} already exists, skipping save");
        return existingTransaction;
    }

    var transaction = new TransactionRecord
    {
        TransactionId = payload.TransactionId,
        Event = payload.Event,
        Amount = payload.Amount,
        Currency = payload.Currency,
        Timestamp = string.IsNullOrEmpty(payload.Timestamp) ? DateTime.UtcNow : DateTime.Parse(payload.Timestamp),
        ProcessedAt = DateTime.UtcNow,
        Status = status,
        ErrorMessage = errorMessage,
        IntegrityValidated = integrityValidated,
        AuthenticityValidated = authenticityValidated,
        DataMismatchDetected = dataMismatchDetected,
        Nonce = nonce,
        RequestId = requestId,
        ClientIp = clientIp,
        UserAgent = userAgent,
        RequestFingerprint = requestFingerprint,
        RawPayload = rawPayload,
        ConfirmationAttempts = 0
    };

    dbContext.Transactions.Add(transaction);
    await dbContext.SaveChangesAsync();

    app.Logger.LogInformation($"DATABASE: Saved transaction {payload.TransactionId} with status: {status}");
    return transaction;
}

async Task UpdateTransactionConfirmationStatus(
    WebhookDbContext dbContext,
    string transactionId,
    string status,
    int confirmationAttempts,
    DateTime? confirmedAt = null,
    string? confirmationError = null)
{
    var transaction = await dbContext.Transactions
        .FirstOrDefaultAsync(t => t.TransactionId == transactionId);

    if (transaction != null)
    {
        transaction.Status = status;
        transaction.ConfirmationAttempts = confirmationAttempts;
        transaction.ConfirmedAt = confirmedAt;
        transaction.ConfirmationError = confirmationError;

        await dbContext.SaveChangesAsync();
        app.Logger.LogInformation($"DATABASE: Updated transaction {transactionId} confirmation status: {status}");
    }
}

// Start the server
app.Logger.LogInformation("Webhook server starting up with comprehensive validation and confirmation system...");
app.Logger.LogInformation($"HMAC secret configured: {WEBHOOK_SECRET[..10]}...");
app.Logger.LogInformation($"Authenticity checks: {(ENABLE_AUTHENTICITY_CHECKS ? "ENABLED" : "DISABLED")}");
app.Logger.LogInformation($"Strict timing: {(ENABLE_STRICT_TIMING ? "ENABLED" : "DISABLED")}");
app.Logger.LogInformation($"Trusted IPs: {string.Join(", ", trustedIPs)}");
app.Logger.LogInformation($"Confirmation system: ENABLED - Max retries: {MAX_CONFIRMATION_RETRIES}, Retry interval: {CONFIRMATION_RETRY_INTERVAL.TotalSeconds}s");
app.Logger.LogInformation($"Confirmation endpoint: {CONFIRMATION_ENDPOINT}");
app.Logger.LogInformation("Database persistence: ENABLED - SQLite database: webhook_transactions.db");
app.Logger.LogInformation("Available endpoints: /webhook, /transactions, /transaction-stats, /confirmation-stats");
app.Urls.Add("http://localhost:5000");
app.Run();

// Database Models
public class TransactionRecord
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(100)]
    public string TransactionId { get; set; } = "";

    [Required]
    [MaxLength(50)]
    public string Event { get; set; } = "";

    [Column(TypeName = "decimal(18,2)")]
    public decimal Amount { get; set; }

    [Required]
    [MaxLength(10)]
    public string Currency { get; set; } = "";

    public DateTime Timestamp { get; set; }

    public DateTime ProcessedAt { get; set; }

    [MaxLength(20)]
    public string Status { get; set; } = ""; // "Confirmed", "Cancelled", "Failed"

    [MaxLength(500)]
    public string? ErrorMessage { get; set; }

    // Security and validation flags
    public bool IntegrityValidated { get; set; }
    public bool AuthenticityValidated { get; set; }
    public bool DataMismatchDetected { get; set; }

    [MaxLength(100)]
    public string? Nonce { get; set; }

    [MaxLength(100)]
    public string? RequestId { get; set; }

    [MaxLength(45)]
    public string? ClientIp { get; set; }

    [MaxLength(200)]
    public string? UserAgent { get; set; }

    [MaxLength(64)]
    public string? RequestFingerprint { get; set; }

    // Confirmation details
    public int ConfirmationAttempts { get; set; }
    public DateTime? ConfirmedAt { get; set; }

    [MaxLength(1000)]
    public string? ConfirmationError { get; set; }

    // Raw payload for audit
    [MaxLength(4000)]
    public string? RawPayload { get; set; }
}

// Database Context
public class WebhookDbContext : DbContext
{
    public WebhookDbContext(DbContextOptions<WebhookDbContext> options) : base(options) { }

    public DbSet<TransactionRecord> Transactions { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TransactionRecord>(entity =>
        {
            entity.HasIndex(e => e.TransactionId).IsUnique();
            entity.HasIndex(e => e.ProcessedAt);
            entity.HasIndex(e => e.Status);
            entity.HasIndex(e => new { e.Event, e.Status });
        });
    }
}

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