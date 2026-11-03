# Superloop App 2.0 passwordless authentication discovery

## Status

The current integration authenticates against legacy Superloop/Exetel
services. Superloop's App 2.0 uses email, postcode and a one-time code.
As of 2026-11-03 there is no verified public API contract for sending
or exchanging the new codes. **Do not guess endpoints or payloads.**

The experimental existing-token option in this branch checks whether
an already-authenticated Superloop session token is accepted by the
legacy `getServices` endpoint. It is a compatibility test only.

## Capturing a safe request *shape*

If the same passwordless login is available in a browser:

1. Open the real Superloop login page. Open browser developer tools
   (Network tab) and filter to Fetch/XHR.
2. Perform one normal login with your own account. Do not automate
   repeated login requests or share the OTP.
3. Identify the requests corresponding to: (a) email/postcode submission,
   (b) OTP request/channel selection, and (c) OTP verification.
4. Record only the **hostname, path, method, request property names,
   response property names, and status codes**. Where a nested object or
   response cookie is necessary, record its NAME only.
5. Replace all values with invented placeholders *before* sharing them.
   E.g., `{"email":"<redacted>","postcode":"<redacted>"}`.
6. Record separately whether the returned token authenticates a data
   request, and the hostname/path of that data request.

**Never share** a raw HAR, auth headers, cookies, Bearer/JWT or refresh
tokens, OTPs, personal email, account/customer IDs, postcodes, device
identifiers, session headers, signatures or full request/response
bodies. HAR exports can contain all of these. Do not attempt to bypass
certificate pinning, disable TLS verification or brute-force endpoints.

If the email/postcode flow is **mobile app only**, browser network
inspection will not reveal the relevant calls. In that case, wait for
a documented/verified API contract rather than assume the old API is
still usable.

## Acceptance criteria for a proper OTP implementation

- Home Assistant config flow prompts for email, postcode and OTP.
- OTP is requested once per setup attempt. Repeated invalid requests are
  not automatically retried.
- Challenges are tied to the session, and expired/incorrect codes show
  actionable errors without logging code values.
- The new token is exchanged/persisted using verified response fields.
- Refresh/expiry/re-authentication works without storing an OTP.
- Data endpoints and Speed Boost are verified with the new token.
- Existing legacy password/token config entries continue to work.
- Tests cover failed challenge, bad/expired OTP, token invalidation,
  retries and no sensitive data in logs.
