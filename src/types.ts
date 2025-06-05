export type Bindings = {
	__DEV__: string
	DURABLE_OBJECT: DurableObjectNamespace
	DB: D1Database
	RPC_URLS: string
	WORKER_URLS: string
	PRIVATE_KEY: string
	REPRESENTATIVE: string
	ADMIN_TOKEN: string
	TURNSTILE_SECRET?: string
	HCAPTCHA_SECRET?: string
	ALLOW_ORIGIN?: string
	DEBUG: string
}

export interface DropData {
	hash: string
	account: string
	amount: string
	country: string
	timestamp: number
	took: number
	is_proxy: boolean
}
