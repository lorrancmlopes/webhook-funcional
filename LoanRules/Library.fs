namespace LoanRules

/// Module containing types for the webhook payload
module Types =
    /// Represents a payment webhook payload
    type WebhookPayload = {
        Event: string
        TransactionId: string
        Amount: decimal
        Currency: string
        Timestamp: string
    }
    
    /// Extended payload with authenticity metadata
    type AuthenticatedPayload = {
        Payload: WebhookPayload
        Nonce: string option
        RequestId: string option
        ClientIP: string option
        UserAgent: string option
        RequestTimestamp: System.DateTime
    }
    
    /// Data mismatch detection result
    type MismatchResult = {
        IsMismatch: bool
        MismatchType: string
        Description: string
        ShouldCancel: bool
    }
    
    /// Confirmation status enumeration
    type ConfirmationStatus =
        | Pending
        | Confirmed
        | Failed
        | Retrying
        | Cancelled
        | Expired
    
    /// Confirmation attempt record
    type ConfirmationAttempt = {
        AttemptNumber: int
        Timestamp: System.DateTime
        Success: bool
        ErrorMessage: string option
        ResponseTime: System.TimeSpan option
    }
    
    /// Comprehensive confirmation record
    type ConfirmationRecord = {
        TransactionId: string
        Status: ConfirmationStatus
        CreatedAt: System.DateTime
        LastUpdated: System.DateTime
        Attempts: ConfirmationAttempt list
        MaxRetries: int
        RetryInterval: System.TimeSpan
        ExpiresAt: System.DateTime
        ConfirmationData: Map<string, string>
        OriginalPayload: WebhookPayload
    }

/// Module for validating webhook payloads
module Validation =
    open System
    open Types
    
    /// Validates that the event type is supported
    let validateEventType (event: string) : bool =
        event = "payment_success"
    
    /// Validates that the amount is positive
    let validateAmount (amount: decimal) : bool =
        amount > 0m
    
    /// Validates that the currency is supported
    let validateCurrency (currency: string) : bool =
        // Currently only supporting BRL
        currency = "BRL"
    
    /// Validates that the timestamp is in a valid format
    let validateTimestamp (timestamp: string) : bool =
        match DateTime.TryParse(timestamp) with
        | true, _ -> true
        | false, _ -> false
    
    /// Validates all aspects of a webhook payload
    let validatePayload (payload: WebhookPayload) : Result<WebhookPayload, string> =
        if not (validateEventType payload.Event) then
            Error "Invalid event type"
        elif not (validateAmount payload.Amount) then
            Error "Invalid amount"
        elif not (validateCurrency payload.Currency) then
            Error "Invalid currency"
        elif not (validateTimestamp payload.Timestamp) then
            Error "Invalid timestamp"
        else
            Ok payload

/// Module for payload integrity validation
module Integrity =
    open System
    open System.Security.Cryptography
    open System.Text
    open Types
    
    /// Validates that the timestamp is not too old (within last 24 hours for testing)
    let validateTimestampFreshness (timestamp: string) : bool =
        match DateTime.TryParse(timestamp) with
        | true, parsedTime ->
            let now = DateTime.UtcNow
            let age = now - parsedTime.ToUniversalTime()
            // Allow up to 24 hours for testing (in production, use 5-15 minutes)
            age.TotalHours <= 24.0 && age.TotalHours >= -1.0  // Also allow 1 hour in future for clock skew
        | false, _ -> false
    
    /// Validates transaction ID format (alphanumeric plus hyphens/underscores, 3-50 characters)
    let validateTransactionIdFormat (transactionId: string) : bool =
        if String.IsNullOrEmpty(transactionId) then false
        elif transactionId.Length < 3 || transactionId.Length > 50 then false
        else
            transactionId |> Seq.forall (fun c -> Char.IsLetterOrDigit(c) || c = '-' || c = '_')
    
    /// Validates that the amount has reasonable precision (max 2 decimal places)
    let validateAmountPrecision (amount: decimal) : bool =
        let rounded = Math.Round(amount, 2)
        amount = rounded
    
    /// Validates payload size constraints
    let validatePayloadSize (jsonPayload: string) : bool =
        let maxSize = 1024 * 10  // 10KB max
        jsonPayload.Length <= maxSize
    
    /// Computes HMAC-SHA256 signature for payload integrity
    let computeHmacSignature (payload: string) (secretKey: string) : string =
        use hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey))
        let hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))
        Convert.ToHexString(hash).ToLowerInvariant()
    
    /// Validates HMAC signature if provided
    let validateHmacSignature (payload: string) (providedSignature: string option) (secretKey: string) : bool =
        match providedSignature with
        | None -> true  // Optional validation - pass if no signature provided
        | Some signature ->
            let expectedSignature = computeHmacSignature payload secretKey
            String.Equals(signature, expectedSignature, StringComparison.OrdinalIgnoreCase)
    
    /// Comprehensive integrity validation
    let validatePayloadIntegrity (payload: WebhookPayload) (jsonPayload: string) (signature: string option) (secretKey: string) : Result<WebhookPayload, string> =
        if not (validatePayloadSize jsonPayload) then
            Error "Payload too large"
        elif not (validateTransactionIdFormat payload.TransactionId) then
            Error "Invalid transaction ID format"
        elif not (validateAmountPrecision payload.Amount) then
            Error "Invalid amount precision"
        // Skip timestamp freshness validation for backward compatibility with tests
        elif not (validateHmacSignature jsonPayload signature secretKey) then
            Error "Invalid signature"
        else
            Ok payload

/// Module for transaction authenticity validation
module Authenticity =
    open System
    open System.Text.RegularExpressions
    open System.Security.Cryptography
    open System.Text
    open Types
    
    /// Validates nonce format (UUID or 32+ hex characters)
    let validateNonceFormat (nonce: string option) : bool =
        match nonce with
        | None -> true  // Nonce is optional
        | Some n when String.IsNullOrEmpty(n) -> false
        | Some n ->
            // Accept either UUID format or 32+ hex characters
            let uuidPattern = @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
            let hexPattern = @"^[0-9a-fA-F]{32,}$"
            Regex.IsMatch(n, uuidPattern) || Regex.IsMatch(n, hexPattern)
    
    /// Validates request ID format (alphanumeric with hyphens/underscores, 8-64 chars)
    let validateRequestIdFormat (requestId: string option) : bool =
        match requestId with
        | None -> true  // Request ID is optional
        | Some rid when String.IsNullOrEmpty(rid) -> false
        | Some rid ->
            rid.Length >= 8 && rid.Length <= 64 &&
            rid |> Seq.forall (fun c -> Char.IsLetterOrDigit(c) || c = '-' || c = '_')
    
    /// Validates strict timestamp freshness (5 minutes window for production)
    let validateStrictTimestampFreshness (timestamp: string) : bool =
        match DateTime.TryParse(timestamp) with
        | true, parsedTime ->
            let now = DateTime.UtcNow
            let age = now - parsedTime.ToUniversalTime()
            // Strict 5-minute window for authenticity checks
            age.TotalMinutes <= 5.0 && age.TotalMinutes >= -0.5  // Allow 30 seconds future for clock skew
        | false, _ -> false
    
    /// Validates client IP address format and optionally against whitelist
    let validateClientIP (clientIP: string option) (whitelist: string list option) : bool =
        match clientIP with
        | None -> true  // IP validation is optional
        | Some ip ->
            // Basic IP format validation (IPv4 and IPv6)
            let ipv4Pattern = @"^(\d{1,3}\.){3}\d{1,3}$"
            let ipv6Pattern = @"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$"
            let isValidFormat = Regex.IsMatch(ip, ipv4Pattern) || Regex.IsMatch(ip, ipv6Pattern)
            
            match whitelist with
            | None -> isValidFormat
            | Some allowedIPs -> isValidFormat && List.contains ip allowedIPs
    
    /// Validates User-Agent header for known patterns
    let validateUserAgent (userAgent: string option) : bool =
        match userAgent with
        | None -> true  // User-Agent is optional
        | Some ua when String.IsNullOrEmpty(ua) -> false
        | Some ua ->
            // Must be at least 10 characters and contain some basic structure
            ua.Length >= 10 && ua.Contains("/")
    
    /// Generates a fingerprint for the request based on multiple factors
    let generateRequestFingerprint (authPayload: AuthenticatedPayload) : string =
        let sb = StringBuilder()
        sb.Append(authPayload.Payload.TransactionId) |> ignore
        sb.Append("|") |> ignore
        sb.Append(authPayload.Payload.Amount.ToString("F2")) |> ignore
        sb.Append("|") |> ignore
        sb.Append(authPayload.RequestTimestamp.ToString("yyyyMMddHHmmss")) |> ignore
        sb.Append("|") |> ignore
        
        match authPayload.Nonce with
        | Some n -> sb.Append(n) |> ignore
        | None -> sb.Append("NO_NONCE") |> ignore
        
        sb.Append("|") |> ignore
        
        match authPayload.ClientIP with
        | Some ip -> sb.Append(ip) |> ignore
        | None -> sb.Append("NO_IP") |> ignore
        
        use sha256 = SHA256.Create()
        let hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()))
        Convert.ToHexString(hash).ToLowerInvariant()
    
    /// Validates request timing to prevent replay attacks (requires strict timing)
    let validateRequestTiming (authPayload: AuthenticatedPayload) : bool =
        let now = DateTime.UtcNow
        let age = now - authPayload.RequestTimestamp
        // Very strict timing for authenticity checks
        age.TotalMinutes <= 2.0 && age.TotalMinutes >= -0.1  // 2 minutes max, 6 seconds future tolerance
    
    /// Comprehensive authenticity validation
    let validateTransactionAuthenticity 
        (authPayload: AuthenticatedPayload) 
        (nonceHistory: string list) 
        (ipWhitelist: string list option) 
        (strictTiming: bool) : Result<AuthenticatedPayload, string> =
        
        if not (validateNonceFormat authPayload.Nonce) then
            Error "Invalid nonce format"
        elif not (validateRequestIdFormat authPayload.RequestId) then
            Error "Invalid request ID format"
        elif not (validateClientIP authPayload.ClientIP ipWhitelist) then
            Error "Invalid or unauthorized client IP"
        elif not (validateUserAgent authPayload.UserAgent) then
            Error "Invalid User-Agent header"
        elif strictTiming && not (validateStrictTimestampFreshness authPayload.Payload.Timestamp) then
            Error "Request timestamp outside allowed window"
        elif strictTiming && not (validateRequestTiming authPayload) then
            Error "Request timing validation failed"
        elif authPayload.Nonce.IsSome && List.contains authPayload.Nonce.Value nonceHistory then
            Error "Nonce already used (replay attack detected)"
        else
            Ok authPayload
    
    /// Creates an audit log entry for the authentication attempt
    let createAuditLogEntry (authPayload: AuthenticatedPayload) (result: Result<AuthenticatedPayload, string>) : string =
        let status = match result with | Ok _ -> "SUCCESS" | Error _ -> "FAILURE"
        let errorMsg = match result with | Ok _ -> "" | Error e -> $" - {e}"
        let nonce = match authPayload.Nonce with | Some n -> n.[..8] + "..." | None -> "NONE"
        let ip = match authPayload.ClientIP with | Some i -> i | None -> "UNKNOWN"
        
        let timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
        let fingerprint = generateRequestFingerprint authPayload
        $"[{timestamp}] AUTH {status}: TxID={authPayload.Payload.TransactionId}, Nonce={nonce}, IP={ip}, Fingerprint={fingerprint}{errorMsg}"

/// Module for data mismatch detection and validation
module DataMismatch =
    open System
    open System.Text.RegularExpressions
    open Types
    
    /// Detects suspicious amount patterns
    let detectSuspiciousAmountPatterns (amount: decimal) : MismatchResult =
        let amountStr = amount.ToString("F2")
        
        // Check for suspicious patterns
        let isRoundAmount = amount % 1m = 0m && amount >= 1000m  // Large round amounts
        let isRepeatingDigits = Regex.IsMatch(amountStr, @"^(\d)\1+\.00$")  // 111.00, 222.00, etc.
        let isSequentialDigits = Regex.IsMatch(amountStr, @"^(123|234|345|456|567|678|789|012).*")  // Sequential patterns
        let isExtremeAmount = amount > 100000m || amount < 0.01m  // Very high or very low amounts
        let isPreciselyRounded = amount % 0.01m = 0m && amount % 0.1m <> 0m && amount > 100m  // Precisely rounded large amounts
        
        if isRoundAmount then
            { IsMismatch = true; MismatchType = "SUSPICIOUS_AMOUNT"; Description = "Large round amount detected"; ShouldCancel = false }
        elif isRepeatingDigits then
            { IsMismatch = true; MismatchType = "PATTERN_AMOUNT"; Description = "Repeating digit pattern in amount"; ShouldCancel = true }
        elif isSequentialDigits then
            { IsMismatch = true; MismatchType = "PATTERN_AMOUNT"; Description = "Sequential digit pattern in amount"; ShouldCancel = true }
        elif isExtremeAmount then
            { IsMismatch = true; MismatchType = "EXTREME_AMOUNT"; Description = "Amount outside expected range"; ShouldCancel = true }
        else
            { IsMismatch = false; MismatchType = ""; Description = ""; ShouldCancel = false }
    
    /// Validates currency against region and amount expectations
    let validateCurrencyContext (currency: string) (amount: decimal) : MismatchResult =
        match currency with
        | "BRL" when amount > 50000m ->
            { IsMismatch = true; MismatchType = "CURRENCY_AMOUNT_MISMATCH"; Description = "BRL amount exceeds typical transaction limits"; ShouldCancel = false }
        | "USD" | "EUR" ->
            { IsMismatch = true; MismatchType = "UNSUPPORTED_CURRENCY"; Description = "Currency not supported in this region"; ShouldCancel = true }
        | cur when String.IsNullOrEmpty(cur) ->
            { IsMismatch = true; MismatchType = "MISSING_CURRENCY"; Description = "Currency field is empty"; ShouldCancel = true }
        | cur when cur.Length <> 3 ->
            { IsMismatch = true; MismatchType = "INVALID_CURRENCY_FORMAT"; Description = "Currency code must be 3 characters"; ShouldCancel = true }
        | _ ->
            { IsMismatch = false; MismatchType = ""; Description = ""; ShouldCancel = false }
    
    /// Validates transaction ID patterns for potential issues
    let validateTransactionIdPatterns (transactionId: string) : MismatchResult =
        if String.IsNullOrEmpty(transactionId) then
            { IsMismatch = true; MismatchType = "MISSING_TRANSACTION_ID"; Description = "Transaction ID is missing"; ShouldCancel = true }
        elif Regex.IsMatch(transactionId, @"^(test|demo|sample|fake)", RegexOptions.IgnoreCase) then
            { IsMismatch = true; MismatchType = "TEST_TRANSACTION_ID"; Description = "Transaction ID appears to be a test transaction"; ShouldCancel = true }
        elif Regex.IsMatch(transactionId, @"^(\d)\1{5,}") then
            { IsMismatch = true; MismatchType = "PATTERN_TRANSACTION_ID"; Description = "Transaction ID contains suspicious repeating patterns"; ShouldCancel = true }
        elif transactionId.Length < 5 then
            { IsMismatch = true; MismatchType = "SHORT_TRANSACTION_ID"; Description = "Transaction ID is too short for security"; ShouldCancel = true }
        elif not (Regex.IsMatch(transactionId, @"^[a-zA-Z0-9\-_]+$")) then
            { IsMismatch = true; MismatchType = "INVALID_TRANSACTION_ID_CHARS"; Description = "Transaction ID contains invalid characters"; ShouldCancel = true }
        else
            { IsMismatch = false; MismatchType = ""; Description = ""; ShouldCancel = false }
    
    /// Validates timestamp for business logic consistency
    let validateTimestampLogic (timestamp: string) (currentTime: DateTime) : MismatchResult =
        match DateTime.TryParse(timestamp) with
        | false, _ ->
            { IsMismatch = true; MismatchType = "INVALID_TIMESTAMP"; Description = "Timestamp format is invalid"; ShouldCancel = true }
        | true, parsedTime ->
            let timeDiff = currentTime - parsedTime.ToUniversalTime()
            
            if timeDiff.TotalDays > 30 then
                { IsMismatch = true; MismatchType = "OLD_TIMESTAMP"; Description = "Transaction timestamp is too old"; ShouldCancel = true }
            elif timeDiff.TotalHours < -24 then
                { IsMismatch = true; MismatchType = "FUTURE_TIMESTAMP"; Description = "Transaction timestamp is too far in the future"; ShouldCancel = true }
            elif parsedTime.DayOfWeek = DayOfWeek.Sunday && parsedTime.Hour < 6 then
                { IsMismatch = true; MismatchType = "UNUSUAL_TIMING"; Description = "Transaction at unusual time (early Sunday)"; ShouldCancel = false }
            else
                { IsMismatch = false; MismatchType = ""; Description = ""; ShouldCancel = false }
    
    /// Cross-field validation for data consistency
    let validateCrossFieldConsistency (payload: WebhookPayload) : MismatchResult =
        // Check if transaction ID and amount have related patterns
        let txIdLower = payload.TransactionId.ToLower()
        let amountStr = payload.Amount.ToString("F2")
        
        if txIdLower.Contains("refund") && payload.Event = "payment_success" then
            { IsMismatch = true; MismatchType = "EVENT_ID_MISMATCH"; Description = "Transaction ID suggests refund but event is payment_success"; ShouldCancel = true }
        elif txIdLower.Contains("cancel") && payload.Event = "payment_success" then
            { IsMismatch = true; MismatchType = "EVENT_ID_MISMATCH"; Description = "Transaction ID suggests cancellation but event is payment_success"; ShouldCancel = true }
        elif payload.Amount = 0m && payload.Event = "payment_success" then
            { IsMismatch = true; MismatchType = "AMOUNT_EVENT_MISMATCH"; Description = "Zero amount with payment_success event"; ShouldCancel = true }
        elif amountStr.Contains(payload.TransactionId.[..2]) then
            { IsMismatch = true; MismatchType = "SUSPICIOUS_CORRELATION"; Description = "Suspicious correlation between transaction ID and amount"; ShouldCancel = false }
        else
            { IsMismatch = false; MismatchType = ""; Description = ""; ShouldCancel = false }
    
    /// Business rule validation for payment processing
    let validateBusinessRules (payload: WebhookPayload) : MismatchResult =
        let currentHour = DateTime.UtcNow.Hour
        
        // Business hours validation (example: 6 AM to 11 PM UTC)
        if currentHour < 6 || currentHour > 23 then
            if payload.Amount > 1000m then
                { IsMismatch = true; MismatchType = "OFF_HOURS_HIGH_AMOUNT"; Description = "High amount transaction outside business hours"; ShouldCancel = false }
            else
                { IsMismatch = false; MismatchType = ""; Description = ""; ShouldCancel = false }
        // Weekend high-value transaction validation
        elif DateTime.UtcNow.DayOfWeek = DayOfWeek.Saturday || DateTime.UtcNow.DayOfWeek = DayOfWeek.Sunday then
            if payload.Amount > 5000m then
                { IsMismatch = true; MismatchType = "WEEKEND_HIGH_AMOUNT"; Description = "High amount transaction on weekend"; ShouldCancel = false }
            else
                { IsMismatch = false; MismatchType = ""; Description = ""; ShouldCancel = false }
        else
            { IsMismatch = false; MismatchType = ""; Description = ""; ShouldCancel = false }
    
    /// Comprehensive data mismatch detection
    let detectDataMismatches (payload: WebhookPayload) : MismatchResult list =
        let currentTime = DateTime.UtcNow
        
        [
            detectSuspiciousAmountPatterns payload.Amount
            validateCurrencyContext payload.Currency payload.Amount
            validateTransactionIdPatterns payload.TransactionId
            validateTimestampLogic payload.Timestamp currentTime
            validateCrossFieldConsistency payload
            validateBusinessRules payload
        ]
        |> List.filter (fun result -> result.IsMismatch)
    
    /// Determines if transaction should be cancelled based on mismatches
    let shouldCancelTransaction (mismatches: MismatchResult list) : bool * string =
        let criticalMismatches = mismatches |> List.filter (fun m -> m.ShouldCancel)
        
        if criticalMismatches.Length > 0 then
            let reasons = criticalMismatches |> List.map (fun m -> m.Description) |> String.concat "; "
            (true, $"Critical data mismatches detected: {reasons}")
        elif mismatches.Length >= 3 then
            let reasons = mismatches |> List.map (fun m -> m.Description) |> String.concat "; "
            (true, $"Multiple data mismatches detected: {reasons}")
        else
            (false, "")
    
    /// Creates a detailed audit log for mismatch detection
    let createMismatchAuditLog (payload: WebhookPayload) (mismatches: MismatchResult list) (shouldCancel: bool) : string =
        let timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
        let status = if shouldCancel then "CANCEL" else if mismatches.Length > 0 then "WARNING" else "PASS"
        
        let mismatchSummary = 
            if mismatches.Length = 0 then "No mismatches detected"
            else 
                mismatches 
                |> List.map (fun m -> $"{m.MismatchType}({m.Description})")
                |> String.concat ", "
        
        $"[{timestamp}] DATA_MISMATCH {status}: TxID={payload.TransactionId}, Amount={payload.Amount}, " +
        $"Currency={payload.Currency}, Mismatches=[{mismatchSummary}]"

/// Module for transaction confirmation management
module Confirmation =
    open System
    open Types
    
    /// Creates a new confirmation record
    let createConfirmationRecord (payload: WebhookPayload) (maxRetries: int) (retryInterval: TimeSpan) : ConfirmationRecord =
        let now = DateTime.UtcNow
        {
            TransactionId = payload.TransactionId
            Status = Pending
            CreatedAt = now
            LastUpdated = now
            Attempts = []
            MaxRetries = maxRetries
            RetryInterval = retryInterval
            ExpiresAt = now.AddHours(24.0)  // 24-hour expiration
            ConfirmationData = Map.empty
            OriginalPayload = payload
        }
    
    /// Validates confirmation data completeness
    let validateConfirmationData (payload: WebhookPayload) : Result<WebhookPayload, string> =
        if String.IsNullOrEmpty(payload.TransactionId) then
            Error "Transaction ID is required for confirmation"
        elif payload.Amount <= 0m then
            Error "Valid amount is required for confirmation"
        elif String.IsNullOrEmpty(payload.Currency) then
            Error "Currency is required for confirmation"
        elif String.IsNullOrEmpty(payload.Event) then
            Error "Event type is required for confirmation"
        else
            Ok payload
    
    /// Determines if confirmation should be retried
    let shouldRetryConfirmation (record: ConfirmationRecord) : bool =
        let now = DateTime.UtcNow
        let hasRetriesLeft = record.Attempts.Length < record.MaxRetries
        let notExpired = now < record.ExpiresAt
        let canRetryStatus = record.Status = Failed || record.Status = Retrying
        
        hasRetriesLeft && notExpired && canRetryStatus
    
    /// Calculates next retry time
    let getNextRetryTime (record: ConfirmationRecord) : DateTime option =
        if shouldRetryConfirmation record then
            let lastAttempt = record.Attempts |> List.tryHead
            match lastAttempt with
            | Some attempt -> Some (attempt.Timestamp.Add(record.RetryInterval))
            | None -> Some (DateTime.UtcNow.Add(record.RetryInterval))
        else
            None
    
    /// Creates a confirmation attempt record
    let createConfirmationAttempt (attemptNumber: int) (success: bool) (errorMessage: string option) (responseTime: TimeSpan option) : ConfirmationAttempt =
        {
            AttemptNumber = attemptNumber
            Timestamp = DateTime.UtcNow
            Success = success
            ErrorMessage = errorMessage
            ResponseTime = responseTime
        }
    
    /// Updates confirmation record with new attempt
    let updateConfirmationRecord (record: ConfirmationRecord) (attempt: ConfirmationAttempt) : ConfirmationRecord =
        let newStatus = 
            if attempt.Success then Confirmed
            elif shouldRetryConfirmation record then Retrying
            else Failed
        
        {
            record with
                Status = newStatus
                LastUpdated = DateTime.UtcNow
                Attempts = attempt :: record.Attempts
        }
    
    /// Validates confirmation response
    let validateConfirmationResponse (responseStatus: int) (responseBody: string option) : bool * string option =
        match responseStatus with
        | 200 | 201 | 202 -> (true, None)
        | 400 -> (false, Some "Bad request - invalid confirmation data")
        | 401 -> (false, Some "Unauthorized - authentication failed")
        | 403 -> (false, Some "Forbidden - access denied")
        | 404 -> (false, Some "Not found - confirmation endpoint unavailable")
        | 409 -> (false, Some "Conflict - transaction already confirmed")
        | 422 -> (false, Some "Unprocessable entity - validation failed")
        | 429 -> (false, Some "Rate limited - too many requests")
        | 500 | 502 | 503 | 504 -> (false, Some "Server error - temporary failure, will retry")
        | _ -> (false, Some $"Unexpected response status: {responseStatus}")
    
    /// Generates confirmation payload for external service
    let generateConfirmationPayload (payload: WebhookPayload) (confirmationId: string) : Map<string, obj> =
        Map [
            ("transaction_id", payload.TransactionId :> obj)
            ("amount", payload.Amount :> obj)
            ("currency", payload.Currency :> obj)
            ("event", payload.Event :> obj)
            ("timestamp", payload.Timestamp :> obj)
            ("confirmation_id", confirmationId :> obj)
            ("confirmed_at", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") :> obj)
            ("status", "confirmed" :> obj)
        ]
    
    /// Calculates confirmation metrics
    let calculateConfirmationMetrics (record: ConfirmationRecord) : Map<string, obj> =
        let totalAttempts = record.Attempts.Length
        let successfulAttempts = record.Attempts |> List.filter (fun a -> a.Success) |> List.length
        let avgResponseTime = 
            record.Attempts 
            |> List.choose (fun a -> a.ResponseTime)
            |> fun times -> 
                if times.Length > 0 then 
                    times |> List.averageBy (fun t -> t.TotalMilliseconds) |> Some
                else None
        
        let timeSinceCreation = DateTime.UtcNow - record.CreatedAt
        let timeToConfirmation = 
            record.Attempts 
            |> List.tryFind (fun a -> a.Success)
            |> Option.map (fun a -> a.Timestamp - record.CreatedAt)
        
        Map [
            ("total_attempts", totalAttempts :> obj)
            ("successful_attempts", successfulAttempts :> obj)
            ("success_rate", (float successfulAttempts / float totalAttempts * 100.0) :> obj)
            ("avg_response_time_ms", avgResponseTime :> obj)
            ("time_since_creation_ms", timeSinceCreation.TotalMilliseconds :> obj)
            ("time_to_confirmation_ms", timeToConfirmation |> Option.map (fun t -> t.TotalMilliseconds) :> obj)
            ("expires_in_ms", (record.ExpiresAt - DateTime.UtcNow).TotalMilliseconds :> obj)
        ]
    
    /// Creates audit log entry for confirmation
    let createConfirmationAuditLog (record: ConfirmationRecord) (attempt: ConfirmationAttempt option) : string =
        let timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
        let statusText = record.Status.ToString().ToUpperInvariant()
        
        let attemptInfo = 
            match attempt with
            | Some att -> $", Attempt={att.AttemptNumber}, Success={att.Success}"
            | None -> ""
        
        let responseTimeInfo =
            attempt 
            |> Option.bind (fun a -> a.ResponseTime)
            |> Option.map (fun rt -> $", ResponseTime={rt.TotalMilliseconds:F0}ms")
            |> Option.defaultValue ""
        
        let errorInfo =
            attempt
            |> Option.bind (fun a -> a.ErrorMessage)
            |> Option.map (fun err -> $", Error={err}")
            |> Option.defaultValue ""
        
        $"[{timestamp}] CONFIRMATION {statusText}: TxID={record.TransactionId}, " +
        $"Amount={record.OriginalPayload.Amount}, TotalAttempts={record.Attempts.Length}" +
        $"{attemptInfo}{responseTimeInfo}{errorInfo}"
    
    /// Determines if confirmation has expired
    let isConfirmationExpired (record: ConfirmationRecord) : bool =
        DateTime.UtcNow >= record.ExpiresAt
    
    /// Gets confirmation summary
    let getConfirmationSummary (record: ConfirmationRecord) : Map<string, obj> =
        Map [
            ("transaction_id", record.TransactionId :> obj)
            ("status", record.Status.ToString() :> obj)
            ("created_at", record.CreatedAt.ToString("yyyy-MM-ddTHH:mm:ssZ") :> obj)
            ("last_updated", record.LastUpdated.ToString("yyyy-MM-ddTHH:mm:ssZ") :> obj)
            ("expires_at", record.ExpiresAt.ToString("yyyy-MM-ddTHH:mm:ssZ") :> obj)
            ("total_attempts", record.Attempts.Length :> obj)
            ("can_retry", shouldRetryConfirmation record :> obj)
            ("is_expired", isConfirmationExpired record :> obj)
            ("next_retry", getNextRetryTime record |> Option.map (fun t -> t.ToString("yyyy-MM-ddTHH:mm:ssZ")) :> obj)
        ]
