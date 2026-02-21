[Skip to main content](https://docs.x402.org/core-concepts/network-and-token-support#content-area)

[x402 home page\\
x402](https://docs.x402.org/)

Search x402 docs...

Ctrl K

- [x402.org](https://x402.org/)
- [GitHub](https://github.com/coinbase/x402)
- [Discord](https://discord.gg/cdp)
- [Vercel Starter](https://vercel.com/templates/ai/x402-ai-starter)

##### Welcome

- [Welcome to x402](https://docs.x402.org/introduction)
- [FAQ](https://docs.x402.org/faq)

##### Getting Started

- [Quickstart for Buyers](https://docs.x402.org/getting-started/quickstart-for-buyers)
- [Quickstart for Sellers](https://docs.x402.org/getting-started/quickstart-for-sellers)

##### Core Concepts

- [HTTP 402](https://docs.x402.org/core-concepts/http-402)
- [Client / Server](https://docs.x402.org/core-concepts/client-server)
- [Facilitator](https://docs.x402.org/core-concepts/facilitator)
- [Wallet](https://docs.x402.org/core-concepts/wallet)
- [Networks & Token Support](https://docs.x402.org/core-concepts/network-and-token-support)

##### Extensions

- [Bazaar (Discovery Layer)](https://docs.x402.org/extensions/bazaar)
- [Sign-In-With-X (SIWX)](https://docs.x402.org/extensions/sign-in-with-x)
- [Payment-Identifier (Idempotency)](https://docs.x402.org/extensions/payment-identifier)

##### Advanced Concepts

- [Lifecycle Hooks](https://docs.x402.org/advanced-concepts/lifecycle-hooks)

##### Guides

- [MCP Server with x402](https://docs.x402.org/guides/mcp-server-with-x402)
- [Migration Guide: V1 to V2](https://docs.x402.org/guides/migration-v1-to-v2)

##### SDK Features

- [SDK Features](https://docs.x402.org/sdk-features)

[x402 home page\\
x402](https://docs.x402.org/)

Search x402 docs...

Ctrl KAsk AI

Search...

Navigation

Core Concepts

Networks & Token Support

Core Concepts

# Networks & Token Support

This page explains which blockchain networks and tokens are supported by x402, and how to extend support to additional networks.

## [​](https://docs.x402.org/core-concepts/network-and-token-support\#v2-network-identifiers-caip-2)  V2 Network Identifiers (CAIP-2)

x402 V2 uses [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) standard network identifiers for unambiguous cross-chain support. This format follows the pattern `namespace:reference`.

### [​](https://docs.x402.org/core-concepts/network-and-token-support\#network-identifier-reference)  Network Identifier Reference

| V1 Name | V2 CAIP-2 ID | Chain ID | Description |
| --- | --- | --- | --- |
| `base-sepolia` | `eip155:84532` | 84532 | Base Sepolia testnet |
| `base` | `eip155:8453` | 8453 | Base mainnet |
| `solana-devnet` | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` | - | Solana Devnet |
| `solana` | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | - | Solana Mainnet |

### [​](https://docs.x402.org/core-concepts/network-and-token-support\#format-explanation)  Format Explanation

- **EVM networks**: `eip155:<chainId>` where chainId is the numeric chain identifier
- **Solana**: `solana:<genesisHash>` where genesisHash is the first 32 bytes of the genesis block hash

## [​](https://docs.x402.org/core-concepts/network-and-token-support\#overview)  Overview

x402 is designed to work across multiple blockchain networks, with different levels of support depending on the facilitator being used. The protocol itself is network-agnostic, but facilitators need to implement network-specific logic for payment verification and settlement.

### [​](https://docs.x402.org/core-concepts/network-and-token-support\#supported-facilitators)  Supported Facilitators

Network support in x402 depends on which facilitator you use. For a complete and up-to-date list of available facilitators and their supported networks, see the [x402 Ecosystem](https://www.x402.org/ecosystem?category=facilitators).

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#x402-org-facilitator)  x402.org Facilitator

- **Supports**: `eip155:84532` (Base Sepolia), `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` (Solana Devnet)
- **Notes**: Recommended for testing and development. This is the default facilitator in the x402 packages and requires no setup.

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#production-facilitators)  Production Facilitators

Multiple production-ready facilitators are available supporting various networks including Base, Solana, Polygon, Avalanche, and more. See the [x402 Ecosystem](https://www.x402.org/ecosystem?category=facilitators) for available options and their documentation.

### [​](https://docs.x402.org/core-concepts/network-and-token-support\#token-support)  Token Support

x402 supports tokens on both EVM and Solana networks:

- **EVM**: Any ERC-20 token that implements the EIP-3009 standard
- **Solana**: Any SPL or token-2022 token

**Important**: Facilitators support networks, not specific tokens — any EIP-3009 compatible token works on EVM networks, and any SPL/token-2022 token works on Solana, for the facilitators that support those networks.

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#evm-eip-3009-requirement)  EVM: EIP-3009 Requirement

Tokens must implement the `transferWithAuthorization` function from the EIP-3009 standard. This enables:

- **Gasless transfers**: The facilitator sponsors gas fees
- **Signature-based authorization**: Users sign transfer authorizations off-chain
- **Secure payments**: Transfers are authorized by cryptographic signatures

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#specifying-payment-amounts)  Specifying Payment Amounts

When configuring payment requirements, you have two options:

1. **Price String** (e.g., `"$0.01"`) \- The system infers USDC as the token
2. **TokenAmount** \- Specify exact atomic units of any EIP-3009 token

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#using-custom-eip-3009-tokens)  Using Custom EIP-3009 Tokens

To use a custom EIP-3009 token, you need three key pieces of information:

1. **Token Address**: The contract address of your EIP-3009 token
2. **EIP-712 Name**: The token’s name for EIP-712 signatures
3. **EIP-712 Version**: The token’s version for EIP-712 signatures

**Finding Token Information on Basescan**You can retrieve the required EIP-712 values from any block explorer:

1. **Name**: Read the `name()` function - [Example on Basescan](https://basescan.org/token/0x833589fcd6edb6e08f4c7c32d4f71b54bda02913#readProxyContract#F16)
2. **Version**: Read the `version()` function - [Example on Basescan](https://basescan.org/token/0x833589fcd6edb6e08f4c7c32d4f71b54bda02913#readProxyContract#F24)

These values are used in the `eip712` nested object when configuring TokenAmount:

Copy

Ask AI

```
{
  eip712: {
    name: "USD Coin",    // From name() function
    version: "2"         // From version() function
  }
}
```

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#solana-spl-tokens-&-token-2022-tokens)  Solana: SPL Tokens & Token 2022 Tokens

On Solana, x402 supports all SPL tokens and Token 2022 tokens. When using facilitators that support Solana or Solana Devnet, payments can be made in any SPL/token-2022 token, including USDC (SPL). No EIP-712 configuration is required on Solana.

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#usdc-the-default-token)  USDC - The Default Token

- **Status**: Supported by default across all networks
- **Why**: USDC implements EIP-3009 and is widely available
- **Networks**: Available on `eip155:8453` (Base), `eip155:84532` (Base Sepolia), and all supported networks

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#why-eip-3009)  Why EIP-3009?

The EIP-3009 standard is essential for x402 because it enables:

1. **Gas abstraction**: Buyers don’t need native tokens (ETH, MATIC, etc.) for gas
2. **One-step payments**: No separate approval transactions required
3. **Universal facilitator support**: Any EIP-3009 token works with any facilitator

### [​](https://docs.x402.org/core-concepts/network-and-token-support\#quick-reference)  Quick Reference

| Facilitator Type | Networks Supported | Production Ready | Requirements |
| --- | --- | --- | --- |
| x402.org (Default) | `eip155:84532`, `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` | Testnet only | None |
| [Production Facilitators](https://www.x402.org/ecosystem?category=facilitators) | Various (Base, Solana, Polygon, Avalanche, etc.) | Yes | Varies |
| Self-hosted | Any EVM network (CAIP-2 format) | Yes | Technical setup |

**Note**: On EVM networks, facilitators support any EIP-3009 compatible token; on Solana, facilitators support any SPL/Token-2022 token.

### [​](https://docs.x402.org/core-concepts/network-and-token-support\#adding-support-for-new-networks)  Adding Support for New Networks

x402 V2 uses dynamic network registration - you can support any EVM network without modifying source files.

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#v2-dynamic-registration-recommended)  V2: Dynamic Registration (Recommended)

In V2, networks are supported through the registration pattern using CAIP-2 identifiers. No source code changes are required:

- TypeScript

- Go

- Python


Copy

Ask AI

```
import { x402ResourceServer, HTTPFacilitatorClient } from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";

const facilitatorClient = new HTTPFacilitatorClient({
  url: "https://your-facilitator.com"  // Facilitator that supports your network
});

const server = new x402ResourceServer(facilitatorClient);
registerExactEvmScheme(server);  // Registers wildcard support for all EVM chains

// Now use any CAIP-2 network identifier in your routes:
const routes = {
  "GET /api/data": {
    accepts: [{\
      scheme: "exact",\
      price: "$0.001",\
      network: "eip155:43114",  // Avalanche mainnet\
      payTo: "0xYourAddress",\
    }],
  },
};
```

Copy

Ask AI

```
import (
    x402http "github.com/coinbase/x402/go/http"
    evm "github.com/coinbase/x402/go/mechanisms/evm/exact/server"
)

facilitatorClient := x402http.NewHTTPFacilitatorClient(&x402http.FacilitatorConfig{
    URL: "https://your-facilitator.com",
})

// Register EVM scheme - supports any CAIP-2 EVM network
schemes := []ginmw.SchemeConfig{
    {Network: x402.Network("eip155:43114"), Server: evm.NewExactEvmScheme()},  // Avalanche
}
```

Copy

Ask AI

```
from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
from x402.http.types import RouteConfig
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.server import x402ResourceServer

# Create facilitator client for your network
facilitator = HTTPFacilitatorClient(
    FacilitatorConfig(url="https://your-facilitator.com")
)

# Create server and register EVM scheme for your network
server = x402ResourceServer(facilitator)
server.register("eip155:43114", ExactEvmServerScheme())  # Avalanche mainnet

# Now use any CAIP-2 network identifier in your routes:
routes: dict[str, RouteConfig] = {
    "GET /api/data": RouteConfig(
        accepts=[\
            PaymentOption(\
                scheme="exact",\
                price="$0.001",\
                network="eip155:43114",  # Avalanche mainnet\
                pay_to="0xYourAddress",\
            ),\
        ],
    ),
}
```

**Key Points:**

- Use CAIP-2 format: `eip155:<chainId>` for any EVM network
- The scheme implementation handles the network automatically
- You only need a facilitator that supports your target network (or run your own)

#### [​](https://docs.x402.org/core-concepts/network-and-token-support\#running-your-own-facilitator)  Running Your Own Facilitator

If you need immediate support or want to test before contributing, you can run your own facilitator.Video Guide: [Adding EVM Chains to x402](https://x.com/jaycoolh/status/1920851551905575164/video/1)**Prerequisites**

1. Access to an RPC endpoint for your target network
2. A wallet with native tokens for gas sponsorship
3. The x402 facilitator code

### [​](https://docs.x402.org/core-concepts/network-and-token-support\#future-network-support)  Future Network Support

The x402 ecosystem is actively expanding network support. Planned additions include:

- Additional L2 networks
- Additional non-EVM chain support
- Cross-chain payment capabilities

### [​](https://docs.x402.org/core-concepts/network-and-token-support\#getting-help)  Getting Help

For help with network integration:

- Join the [x402 Discord community](https://discord.gg/cdp)
- Check the [x402 GitHub repository](https://github.com/coinbase/x402)

### [​](https://docs.x402.org/core-concepts/network-and-token-support\#summary)  Summary

x402’s network support is designed to be extensible while maintaining security and reliability. Whether you’re using the default Base Sepolia (`eip155:84532`) setup for testing or running your own facilitator for custom networks, the protocol provides flexibility for various use cases.Key takeaways:

- Base (`eip155:8453`) and Base Sepolia (`eip155:84532`) have the best out-of-the-box support
- Any EVM network can be supported with a custom facilitator using CAIP-2 format
- Any EIP-3009 token (with `transferWithAuthorization`) works on any facilitator
- Use price strings for USDC or TokenAmount for custom tokens
- Network choice affects gas costs and payment economics
- V2 uses CAIP-2 network identifiers for unambiguous cross-chain support

Next, explore:

- [Quickstart for Sellers](https://docs.x402.org/getting-started/quickstart-for-sellers) — Start accepting payments on supported networks
- [Core Concepts](https://docs.x402.org/core-concepts/http-402) — Learn how x402 works under the hood
- [Facilitator](https://docs.x402.org/core-concepts/facilitator) — Understand the role of facilitators
- [MCP Server](https://docs.x402.org/guides/mcp-server-with-x402) — Set up AI agents to use x402 payments

[Previous](https://docs.x402.org/core-concepts/wallet) [Bazaar (Discovery Layer)The x402 Bazaar is the discovery layer for the x402 ecosystem - a machine-readable catalog that helps developers and AI agents find and integrate with x402-compatible API endpoints.\\
\\
Next](https://docs.x402.org/extensions/bazaar)

[Powered by](https://www.mintlify.com/?utm_campaign=poweredBy&utm_medium=referral&utm_source=coinbase-5dac824f)

Assistant

Responses are generated using AI and may contain mistakes.