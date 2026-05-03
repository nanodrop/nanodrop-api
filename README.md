# NanoDrop API

NanoDrop Faucet REST API.

> ⚠️ API deprecated  
> This API has been internalized  into the main project alongside the frontend and is no longer maintained here.  
> Use the current project: https://github.com/nanodrop/nanodrop.io

## Stack

This project is made with Typescript and was designed to run on the EDGE. It implements:

- [Cloudflare Workers](https://developers.cloudflare.com/workers/): a low cost, fast and scalable serverless environment.
- [Durable Objects](https://developers.cloudflare.com/durable-objects/): allow us to cache Proof of Work with low latency in-memory.
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

Set production secrets:

```
pnpm wrangler secret put PRIVATE_KEY
...
```

Finally, deploy it:

```
pnpm run deploy
```
