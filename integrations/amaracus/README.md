# AMARACUS plugin

This plugin connects your coding agent to [AMARACUS](https://amaracus.tech), an encryption and key management service. It adds the AMARACUS MCP server and one skill that guides the agent when you ask it to encrypt application data.

## What you can do

- List, create, rotate, disable and enable the encryption keys of your organization.
- Encrypt and decrypt text with a key, and compute SHA-2 or SHA-3 digests.
- Get working integration code for Node.js, Python or curl, an explanation of API errors, and security practices.

There is no tool that deletes or revokes keys or that creates API keys, and key material is never returned.

## What you need

An AMARACUS account with an active plan. The first time a tool is used, your client opens the AMARACUS sign-in page in your browser. There you choose one project and environment and tick the permissions the agent may have. Decrypting, rotating and disabling keys are off unless you turn them on. To disconnect, open API Credentials in the AMARACUS console and revoke the entry that starts with "MCP".

## Install

Claude Code:

```
/plugin marketplace add AMARACUS/AMARACUS
/plugin install amaracus@amaracus
```

Codex:

```
codex plugin marketplace add AMARACUS/AMARACUS
```

Gemini CLI:

```
gemini extensions install https://github.com/AMARACUS/AMARACUS
```

Other clients: add `https://api.amaracus.tech/mcp` as a Streamable HTTP MCP server. Instructions for each client are at https://amaracus.tech/mcp/.

## Data

The plugin talks only to https://api.amaracus.tech/mcp. Text you pass to the encrypt, decrypt and hash tools is sent to AMARACUS to perform that operation, and passes through the AI model you are using. See the [privacy policy](https://amaracus.tech/privacy/).

## Licence

Apache-2.0. Support: support@amaracus.tech
