# NanoDrop API

NanoDrop Faucet REST API.

## Stack

This project is made with Typescript and was designed to run on the EDGE. It implements:

- [Cloudflare Workers](https://developers.cloudflare.com/workers/): a low cost, fast and scalable serverless environment.
- [Durable Objects](https://developers.cloudflare.com/durable-objects/): allow us to cache Proof of Work with low latency in-memory.
- [Cloudflare Queues](https://developers.cloudflare.com/queues/): Queue that ingrates with Cloudflare Workers. It guarantee delivery and offload work.
- [Hono](https://hono.dev/): A small, simple, and ultrafast web framework for the Edges.

## Running locally

```
pnpm install
pnpm dev
```

## Deploy

First, authenticate with your Cloudflare account:

```
pnpm wrangler login
```

Add queue:

```
pnpm wrangler queues create nanodrop-queue
```

Set production secrets:

```
pnpm wrangler secret put PRIVATE_KEY
...
```

Finally, deploy it:

```
pnpm run deploy
```
