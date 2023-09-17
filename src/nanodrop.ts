import { Hono } from 'hono'
import { Bindings, DropData } from './types'
import { NanoWalletState } from 'nano-wallet-js'
import NanoWallet from 'nano-wallet-js'
import { errorHandler } from './middlewares'
import { Unit, checkAddress, checkAmount, checkSignature, convert, signBlock, verifyBlock } from 'nanocurrency'
import { TunedBigNumber } from './utils'

const TICKET_EXPIRATION = 1000 * 60 * 5 // 5 minutes
const MIN_DROP_AMOUNT = 0.000001
const MAX_DROP_AMOUNT = 0.01
const DIVIDE_BALANCE_BY = 10000
const PERIOD = 1000 * 60 * 60 * 24 * 7 // 1 week
const MAX_DROPS_PER_IP = 3

export class NanoDrop implements DurableObject {

    app = new Hono<{ Bindings: Bindings }>().onError(errorHandler)
    wallet: NanoWallet
    storage: DurableObjectStorage
    static version = "v0.1.0-alpha.1"
    env: 'development' | 'production'

    constructor(state: DurableObjectState, env: Bindings) {

        this.env = env.ENVIRONMENT

        this.storage = state.storage

        this.wallet = new NanoWallet({
            rpcUrls: env.RPC_URLS.split(','),
            workerUrls: env.WORKER_URLS.split(','),
            privateKey: env.PRIVATE_KEY,
            representative: env.REPRESENTATIVE,
            debug: env.DEBUG === 'true'
        })

        this.wallet.subscribe(async (state) => {
            await this.storage.put('wallet-state', state)
        })

        state.blockConcurrencyWhile(async () => {
            const walletState = await this.storage.get<NanoWalletState>('wallet-state')
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
                return c.json({ error: 'IP header is missing' }, 400)
            }

            // count number of drops from db based on ip
            const count: number = await env.DB.prepare('SELECT COUNT(*) as count FROM drops WHERE ip = ?1 AND timestamp >= ?2').bind(ip, PERIOD).first('count')

            if (count >= MAX_DROPS_PER_IP) {
                return c.json({ error: 'Drop limit reached for your IP' }, 403)
            }

            const country = this.env === 'development' ? '**' : c.req.headers.get('cf-ipcountry')

            if (!country) {
                return c.json({ error: 'Country header is missing' }, 400)
            }

            const isProxy = false
            const proxyCheckedBy = 'nanodrop'

            await env.DB.prepare('INSERT INTO ip_info (ip, country, is_proxy, proxy_checked_by) VALUES (?1, ?2, ?3, ?4) ON CONFLICT do nothing')
                .bind(ip, country, isProxy ? 1 : 0, proxyCheckedBy).run()

            const amount = this.dropAmount()
            if (amount === '0') {
                return c.json({ error: 'Insufficient balance' }, 500)
            }
            const amountNano = convert(amount, { from: Unit.raw, to: Unit.NANO })
            const expiresAt = Date.now() + TICKET_EXPIRATION
            const ticket = await this.generateTicket(ip, amount, expiresAt)
            return c.json({ ticket, amount, amountNano, expiresAt })
        })

        this.app.post('/drop', async (c) => {

            const startedAt = Date.now()

            const payload = await c.req.json()
            if (!payload.account) {
                return c.json({ error: 'Account is required' }, 400)
            }
            if (!checkAddress(payload.account)) {
                return c.json({ error: 'Invalid account' }, 400)
            }
            if (!payload.ticket) {
                return c.json({ error: 'Ticket is required' }, 400)
            }

            const redeemedTickets = await this.storage.get<Record<string, number>>("redeemed_tickets")

            if (redeemedTickets) {
                const tickets = Object.keys(redeemedTickets)
                if (tickets.includes(payload.ticket)) {
                    return c.json({ error: 'Ticket already redeemed' }, 403)
                }
            }

            const { amount, ip, expiresAt } = await this.parseTicket(payload.ticket)

            if (expiresAt < Date.now()) {
                throw new Error('Ticket expired')
            }

            if (this.env !== 'development') {
                const realIp = c.req.headers.get('x-real-ip')
                if (!realIp) {
                    return c.json({ error: 'IP header is missing' }, 400)
                }
                if (realIp !== ip) {
                    if (!realIp) {
                        return c.json({ error: 'Ticket IP mismatch' }, 400)
                    }
                }
            }

            const { hash } = await this.wallet.send(payload.account, amount)

            const timestamp = Date.now()

            // save redeemed ticket with expiresAt for later deletion
            await this.storage.put("redeemed_tickets", {
                ...redeemedTickets,
                [payload.ticket]: expiresAt
            })

            const took = timestamp - startedAt

            // save drop
            await env.DB.prepare('INSERT INTO drops (hash, account, amount, ip, timestamp, took) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
                .bind(hash, payload.account, amount, ip, timestamp, took).run()

            return c.json({ hash, amount })
        })

        this.app.get('/drops', async (c) => {
            const { results } = await env.DB.prepare(`
                SELECT hash, account, amount, took, timestamp, ip_info.country, ip_info.is_proxy
                FROM drops
                INNER JOIN ip_info ON drops.ip = ip_info.ip
            `).all<DropData>();
            return c.json(results?.map((drop) => ({ ...drop, is_proxy: drop.is_proxy ? true : false })) || [])
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
        const balance = this.wallet.balance
        const min = convert(MIN_DROP_AMOUNT.toString(), { from: Unit.NANO, to: Unit.raw })
        const max = convert(MAX_DROP_AMOUNT.toString(), { from: Unit.NANO, to: Unit.raw })
        if (TunedBigNumber(balance).isLessThan(min)) return "0"
        const amount = TunedBigNumber(balance).dividedBy(DIVIDE_BALANCE_BY).toString(10)
        const amountFixed = TunedBigNumber(amount).minus(amount.substring(1, amount.length)).toString(10).replace(/[2-9]/g, '1')
        if (TunedBigNumber(amountFixed).isLessThan(min)) return min
        return TunedBigNumber(amountFixed).isGreaterThan(max) ? max : amountFixed
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

    async parseTicket(ticket: string) {

        const isValidBase64 =
            ticket.length % 4 === 0 &&
            /^[A-Za-z0-9+/]+[=]{0,2}$/.test(ticket)

        if (!isValidBase64) {
            throw new Error('Invalid ticket')
        }

        let data

        try {
            data = JSON.parse(atob(ticket))
        } catch (err) {
            throw new Error('Invalid ticket')
        }

        const { ip, amount, version, expiresAt, signature } = data

        const isValidIPv4OrIpv6 =
            ip.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/) ||
            ip.match(/^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i)

        if (!isValidIPv4OrIpv6 || version !== 0) {
            throw new Error('Invalid ticket')
        }

        if (!checkAmount(amount) || !checkSignature(signature)) {
            throw new Error('Invalid ticket')
        }

        const digest = await crypto.subtle.digest({
            name: 'SHA-256',
        }, new TextEncoder().encode(JSON.stringify({
            ip,
            amount,
            version,
            expiresAt
        })))

        const hash = [...new Uint8Array(digest)]
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')

        const valid = verifyBlock({
            hash,
            publicKey: this.wallet.publicKey,
            signature
        })

        if (!valid) {
            throw new Error('Invalid ticket')
        }

        return {
            ip,
            amount,
            version,
            expiresAt,
            hash,
            signature
        }
    }

    fetch(request: Request) {
        return this.app.fetch(request)
    }
}
