# HIBP Password Leak Checker 🔐

A Python CLI app that checks whether a password has appeared in known breaches
using the Have I Been Pwned k-anonymity API.

## How It Works (Security)

- The password is hashed locally using SHA-1
- Only the first 5 characters of the hash are sent to HIBP
- The full password is NEVER transmitted
- Uses HIBP k-anonymity model for privacy
