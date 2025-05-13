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
