export type Bindings = {
    ENVIRONMENT: 'development' | 'production'
    HONO_QUEUE: Queue<any>
    DURABLE_OBJECT: DurableObjectNamespace
    RPC_URLS: string
    WORKER_URLS: string
    PRIVATE_KEY: string
    REPRESENTATIVE: string
    DEBUG: string
}