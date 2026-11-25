---
name: encrypt-application-data
description: Add encryption of sensitive fields, files or records to an application with AMARACUS, or fix an existing AMARACUS integration. Use when the user asks to encrypt application data with AMARACUS, set up AMARACUS keys, or explain an AMARACUS API error.
---

# Encrypt application data with AMARACUS

1. Find the code that writes and reads the data to protect, and the language of the server. Encryption belongs on the server. Browser and mobile code never holds an AMARACUS API key.
2. Call list_keys. Use an existing ACTIVE key with purpose ENCRYPTION that fits the data, or ask the user for a name and call create_key. Use one key per kind of data.
3. Call get_integration_guide with the topic quickstart, then nodejs, python or curl. Adapt that code to the project's own style, HTTP client and error handling.
4. Read the API key and the key ID from the server's configuration. Ask the user to create the API key in the AMARACUS console with only the scopes the service needs, and to set it themselves. Do not ask them to paste it into the conversation.
5. Encrypt before writing and decrypt after reading. Store the whole envelope string, in a column large enough for it. Send a context (the aad field) that names the table, record and field, such as customers:42:address, and send the same value when decrypting.
6. Handle errors from the API. get_integration_guide with the topic errors lists them. A failed decryption must not fall back to showing the stored envelope as if it were data.
7. Plan for rows that already exist: encrypt them in a batch job, and keep reading old rows until the job is done.
8. Test with made-up data: encrypt, decrypt, a wrong context that must fail, and a missing permission.

Passwords are hashed with scrypt or Argon2id, not encrypted.
