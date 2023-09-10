import { Hono } from 'hono'
import { Bindings } from './types'
import { NanoWalletState } from 'nano-wallet-js'
import NanoWallet from 'nano-wallet-js'
import { errorHandler } from './middlewares'
import { signBlock } from 'nanocurrency'

const TICKET_EXPIRATION = 1000 * 60 * 5 // 5 minutes

export class NanoDrop implements DurableObject {

    app = new Hono<{ Bindings: Bindings }>().onError(errorHandler)
    wallet: NanoWallet
    state: DurableObjectState
    static version = "v0.1.0-alpha.1"
    env: 'development' | 'production'

    constructor(state: DurableObjectState, env: Bindings) {

        this.env = env.ENVIRONMENT

        this.state = state

        this.wallet = new NanoWallet({
            rpcUrls: env.RPC_URLS.split(','),
            workerUrls: env.WORKER_URLS.split(','),
            privateKey: env.PRIVATE_KEY,
            representative: env.REPRESENTATIVE,
            debug: env.DEBUG === 'true'
        })

        this.wallet.subscribe(async (state) => {
            await this.state.storage?.put('wallet-state', state)
        })

        this.state.blockConcurrencyWhile(async () => {
            const walletState = await this.state.storage?.get<NanoWalletState>('wallet-state')
            console.info("... blockCurrency While", { walletState: JSON.stringify(walletState, null, 2) })
            if (walletState) {
                this.wallet.update(walletState)
            }
        })

        this.app.get('/wallet', (c) => {
            const { balance, receivable, frontier, representative } = this.wallet.state
            return c.json({ account: this.wallet.account, balance, receivable, frontier, representative })
        })

        this.app.get('/wallet/receivable-blocks', async (c) => {
            return c.json(this.wallet.receivableBlocks)
        })

        this.app.get('/ticket', async (c) => {
            const ip = this.env === 'development' ? '127.0.0.1' : c.req.headers.get('x-real-ip')
            if (!ip) {
                throw new Error('IP header is missing')
            }
            const amount = this.dropAmount()
            const expiresAt = Date.now() + TICKET_EXPIRATION
            const ticket = await this.generateTicket(ip, amount, expiresAt)
            return c.json({ ticket, amount, expiresAt })
        })

        this.app.post('/drop', async (c) => {
            const payload = await c.req.json()
            if (!payload.account) {
                throw new Error('Account is required')
            }
            const amount = this.dropAmount()
            const { hash } = await this.wallet.send(payload.account, amount)
            return c.json({ hash, amount })
        })

        this.app.post('/sync', async (c) => {
            await this.wallet.sync()
            return c.json({ success: true })
        })

        this.app.post('/receive/:link', async (c) => {
            const link = c.req.param('link')
            const { hash } = await this.wallet.receive(link)
            return c.json({ hash })
        })

        this.app.post('/queue', async (c) => {
            await env.HONO_QUEUE.send({ message: 'Hello queue from Durable Object!' })
            return c.text('Sent to Queue!')
        })
    }

    dropAmount() {
        return '100000000000000000000000000'
    }

    async generateTicket(ip: string, amount: string, expiresAt: number) {

        const version = 0

        const data = {
            ip,
            amount,
            version,
            expiresAt
        }

        const digest = await crypto.subtle.digest({
            name: 'SHA-256',
        }, new TextEncoder().encode(JSON.stringify(data)))

        const hash = [...new Uint8Array(digest)]
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')

        const signature = signBlock({
            hash,
            secretKey: this.wallet.config.privateKey
        })

        const ticket = btoa(JSON.stringify({
            ...data,
            signature
        }))

        return ticket
    }

    fetch(request: Request) {
        return this.app.fetch(request)
    }
}
