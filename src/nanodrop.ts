import { Hono } from 'hono'
import { Bindings, DropData } from './types'
import { NanoWalletState } from 'nano-wallet-js'
import NanoWallet from 'nano-wallet-js'
import { errorHandler } from './middlewares'
import {
	Unit,
	checkAddress,
	checkAmount,
	checkSignature,
	convert,
	signBlock,
	verifyBlock,
} from 'nanocurrency'
import { TunedBigNumber, formatNanoAddress, isValidIPv4OrIpv6 } from './utils'
import { HTTPException } from 'hono/http-exception'

const TICKET_EXPIRATION = 1000 * 60 * 5 // 5 minutes
const MIN_DROP_AMOUNT = 0.000001
const MAX_DROP_AMOUNT = 0.01
const DIVIDE_BALANCE_BY = 10000
const PERIOD = 1000 * 60 * 60 * 24 * 7 // 1 week
const MAX_DROPS_PER_IP = 5
const MAX_DROP_PER_IP_SIMULTANEOUSLY = 3
const ENABLE_LIMIT_PER_IP_IN_DEV = false
const VERIFICATION_REQUIRED_BY_DEFAULT = false
const MAX_DROPS_PER_ACCOUNT = 3
const MAX_TMP_ACCOUNT_BLACKLIST_LENGTH = 10000
const BAN_PROXIES = false

export class NanoDrop implements DurableObject {
	app = new Hono<{ Bindings: Bindings }>().onError(errorHandler)
	wallet: NanoWallet
	storage: DurableObjectStorage
	static version = 'v0.1.0-alpha.1'
	env: 'development' | 'production'
	db: D1Database
	ipTicketQueue: Record<string, Promise<void>[]> = {}

	constructor(state: DurableObjectState, env: Bindings) {
		this.env = env.ENVIRONMENT

		this.storage = state.storage

		this.db = env.DB

		this.wallet = new NanoWallet({
			rpcUrls: env.RPC_URLS.split(','),
			workerUrls: env.WORKER_URLS.split(','),
			privateKey: env.PRIVATE_KEY,
			representative: env.REPRESENTATIVE,
			debug: env.DEBUG === 'true',
		})

		state.blockConcurrencyWhile(async () => {
			await this.init()
		})

		this.app.get('/ticket', async c => {
			if (
				env.ALLOW_ORIGIN &&
				new URL(env.ALLOW_ORIGIN).origin !== c.req.header('origin')
			) {
				return c.json({ error: 'Origin mismatch' }, 400)
			}

			const ip =
				this.env === 'development'
					? '127.0.0.1'
					: c.req.headers.get('x-real-ip')
			if (!ip) {
				return c.json({ error: 'IP header is missing' }, 400)
			}

			const [dropsCount, ipInfo] = await env.DB.batch<Record<string, any>>([
				env.DB.prepare(
					'SELECT COUNT(*) as count FROM drops WHERE ip = ?1 AND timestamp >= ?2',
				).bind(ip, Date.now() - PERIOD),
				env.DB.prepare(`SELECT is_proxy FROM ip_info WHERE ip = ?1`).bind(ip),
			])

			const count = dropsCount.results
				? (dropsCount.results[0].count as number)
				: 0

			if (
				count >= MAX_DROPS_PER_IP &&
				(this.env !== 'development' || ENABLE_LIMIT_PER_IP_IN_DEV)
			) {
				const ipWhitelist =
					(await this.storage.get<string[]>('ip-whitelist')) || []
				if (!ipWhitelist.includes(ip)) {
					return c.json({ error: 'Drop limit reached for your IP' }, 403)
				}
			}

			let isProxy = false

			if (!ipInfo.results?.length) {
				// Retrieve IP info and save on db only the first time

				const country =
					this.env === 'development' ? '**' : c.req.headers.get('cf-ipcountry')

				if (!country) {
					return c.json({ error: 'Country header is missing' }, 400)
				}

				let proxyCheckedBy = 'nanodrop'

				if (this.env !== 'development') {
					try {
						isProxy = await this.checkProxy(ip)
						proxyCheckedBy = 'badip.info'
					} catch (error) {
						// Do not throw
						console.error(`Failed checking IP ${ip}`)
					}
				}

				await env.DB.prepare(
					'INSERT INTO ip_info (ip, country, is_proxy, proxy_checked_by) VALUES (?1, ?2, ?3, ?4) ON CONFLICT do nothing',
				)
					.bind(ip, country, isProxy ? 1 : 0, proxyCheckedBy)
					.run()
			} else {
				isProxy = ipInfo.results[0].is_proxy ? true : false
			}

			if (isProxy && BAN_PROXIES) {
				return c.json({ error: 'Proxies are not allowed' }, 403)
			}

			const amount = this.getDropAmount()
			if (amount === '0') {
				return c.json({ error: 'Insufficient balance' }, 500)
			}
			const amountNano = convert(amount, { from: Unit.raw, to: Unit.NANO })
			const expiresAt = Date.now() + TICKET_EXPIRATION
			const verificationRequired = isProxy || VERIFICATION_REQUIRED_BY_DEFAULT
			const ticket = await this.generateTicket(
				ip,
				amount,
				expiresAt,
				verificationRequired,
			)

			return c.json({
				ticket,
				amount,
				amountNano,
				expiresAt,
				verificationRequired,
			})
		})

		this.app.post('/drop', async c => {
			try {
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

				const account = formatNanoAddress(payload.account)

				if (account === this.wallet.account) {
					return c.json({ error: 'I cannot send to myself' }, 400)
				}

				const ticket = payload.ticket

				const {
					hash: ticketHash,
					amount,
					ip,
					expiresAt,
					verificationRequired,
				} = await this.parseTicket(ticket)

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

				const redeemedTicketHashes = await this.storage.get<
					Record<string, number>
				>('redeemed_ticket_hashes')

				if (redeemedTicketHashes) {
					const tickets = Object.keys(redeemedTicketHashes)
					if (tickets.includes(ticketHash)) {
						return c.json({ error: 'Ticket already redeemed' }, 403)
					}
				}

				const accountIsInTmpBlacklist =
					await this.accountIsInTmpBlacklist(account)

				if (accountIsInTmpBlacklist) {
					return c.json({ error: 'Limit reached for this account' }, 403)
				}

				if (verificationRequired) {
					if (!payload.turnstileToken) {
						return c.json({ error: 'Turnstile token is missing' }, 400)
					}

					const formData = new FormData()
					formData.append('secret', env.TURNSTILE_SECRET)
					formData.append('response', payload.turnstileToken)
					formData.append('remoteip', ip)

					const url =
						'https://challenges.cloudflare.com/turnstile/v0/siteverify'
					const result = await fetch(url, {
						body: formData,
						method: 'POST',
					})

					const outcome = await result.json<{ success: boolean }>()

					if (!outcome.success) {
						return c.json({ error: 'Turnstile token failed' }, 400)
					}
				}

				const dequeue = await this.enqueueIPTicket(ip, ticket)

				try {
					const { hash } = await this.wallet.send(account, amount)

					const timestamp = Date.now()

					const took = timestamp - startedAt

					this.redeemTicket({ hash: ticketHash, expiresAt })

					this.saveDrop({
						hash,
						account,
						amount,
						ip,
						timestamp,
						took,
					})

					return c.json({ hash, amount })
				} finally {
					dequeue()
				}
			} catch (error) {
				if (
					error instanceof Error &&
					(error.message === 'Fork' || error.message === 'Old block')
				) {
					// Fix fork and Old block syncing wallet
					this.wallet.sync()
				}
				throw error
			}
		})

		this.app.get('/drops', async c => {
			const orderBy = c.req.query('orderBy')?.toUpperCase() || 'DESC'
			if (orderBy !== 'ASC' && orderBy !== 'DESC') {
				return c.json({ error: 'Invalid orderBy' }, 400)
			}
			const limit = Number(c.req.query('limit')) || 20
			if (isNaN(limit) || limit < 1 || limit > 100) {
				return c.json({ error: 'Invalid limit' }, 400)
			}
			const offset = Number(c.req.query('offset')) || 0
			if (isNaN(offset) || offset < 0) {
				return c.json({ error: 'Invalid offset' }, 400)
			}
			const { results } = await env.DB.prepare(
				`
                SELECT hash, account, amount, took, timestamp, ip_info.country, ip_info.is_proxy
                FROM drops
                INNER JOIN ip_info ON drops.ip = ip_info.ip
				ORDER BY timestamp ${orderBy}
				LIMIT ${limit}
				OFFSET ${offset}
            `,
			).all<DropData>()
			return c.json(
				results?.map(drop => ({
					...drop,
					is_proxy: drop.is_proxy ? true : false,
				})) || [],
			)
		})

		this.app.get('/wallet', c => {
			const { balance, receivable, frontier, representative } =
				this.wallet.state
			return c.json({
				account: this.wallet.account,
				balance,
				receivable,
				frontier,
				representative,
			})
		})

		this.app.post('/wallet/sync', async c => {
			if (c.req.headers.get('Authorization') !== `Bearer ${env.ADMIN_TOKEN}`) {
				return c.json({ error: 'Unauthorized' }, 401)
			}
			await this.wallet.sync()
			return c.json({ success: true })
		})

		this.app.get('/wallet/receivables', async c => {
			return c.json(this.wallet.receivableBlocks)
		})

		this.app.post('/wallet/receive/:link', async c => {
			if (c.req.headers.get('Authorization') !== `Bearer ${env.ADMIN_TOKEN}`) {
				return c.json({ error: 'Unauthorized' }, 401)
			}
			const link = c.req.param('link')
			const { hash } = await this.wallet.receive(link)
			return c.json({ hash })
		})

		this.app.get('/whitelist/ip', async c => {
			if (c.req.headers.get('Authorization') !== `Bearer ${env.ADMIN_TOKEN}`) {
				return c.json({ error: 'Unauthorized' }, 401)
			}
			const ipWhitelist =
				(await this.storage.get<string[]>('ip-whitelist')) || []
			return c.json(ipWhitelist)
		})

		this.app.put('/whitelist/ip/:ipAddress', async c => {
			/*
				IP whitelist allows faucet testing by Admin
			*/
			if (c.req.headers.get('Authorization') !== `Bearer ${env.ADMIN_TOKEN}`) {
				return c.json({ error: 'Unauthorized' }, 401)
			}
			const ip = c.req.param('ipAddress')

			const isValidIP = isValidIPv4OrIpv6(ip)

			if (!isValidIP) {
				return c.json({ error: 'Invalid IP' }, 400)
			}

			const ipWhitelist =
				(await this.storage.get<string[]>('ip-whitelist')) || []
			if (!ipWhitelist.includes(ip)) {
				await this.storage.put('ip-whitelist', [...ipWhitelist, ip])
			}
			return c.json({ success: true })
		})

		this.app.get('/whitelist/account', async c => {
			if (c.req.headers.get('Authorization') !== `Bearer ${env.ADMIN_TOKEN}`) {
				return c.json({ error: 'Unauthorized' }, 401)
			}
			const accountWhitelist =
				(await this.storage.get<string[]>('account-whitelist')) || []
			return c.json(accountWhitelist)
		})

		this.app.put('/whitelist/account/:account', async c => {
			/*
				Account whitelist allows faucet testing by Admin
			*/
			if (c.req.headers.get('Authorization') !== `Bearer ${env.ADMIN_TOKEN}`) {
				return c.json({ error: 'Unauthorized' }, 401)
			}
			const account = c.req.param('account')

			if (!checkAddress(account)) {
				return c.json({ error: 'Invalid account' }, 400)
			}

			const accountWhitelist =
				(await this.storage.get<string[]>('account-whitelist')) || []
			if (!accountWhitelist.includes(account)) {
				await this.storage.put('account-whitelist', [
					...accountWhitelist,
					formatNanoAddress(account),
				])
			}
			return c.json({ success: true })
		})
	}

	async init() {
		const walletState = await this.storage.get<NanoWalletState>('wallet-state')
		if (walletState) {
			this.wallet.update(walletState)
		}
		this.wallet.subscribe(state => {
			this.storage.put('wallet-state', state)
		})
	}

	getDropAmount() {
		const balance = this.wallet.balance
		const min = convert(MIN_DROP_AMOUNT.toString(), {
			from: Unit.NANO,
			to: Unit.raw,
		})
		const max = convert(MAX_DROP_AMOUNT.toString(), {
			from: Unit.NANO,
			to: Unit.raw,
		})
		if (TunedBigNumber(balance).isLessThan(min)) return '0'
		const amount = TunedBigNumber(balance)
			.dividedBy(DIVIDE_BALANCE_BY)
			.toString(10)
		const amountFixed = TunedBigNumber(amount)
			.minus(amount.substring(1, amount.length))
			.toString(10)
			.replace(/[2-9]/g, '1')
		if (TunedBigNumber(amountFixed).isLessThan(min)) return min
		return TunedBigNumber(amountFixed).isGreaterThan(max) ? max : amountFixed
	}

	async generateTicket(
		ip: string,
		amount: string,
		expiresAt: number,
		verificationRequired: boolean,
	) {
		const version = 1

		const data = {
			ip,
			amount,
			version,
			expiresAt,
			verificationRequired,
		}

		const digest = await crypto.subtle.digest(
			{
				name: 'SHA-256',
			},
			new TextEncoder().encode(JSON.stringify(data)),
		)

		const hash = [...new Uint8Array(digest)]
			.map(b => b.toString(16).padStart(2, '0'))
			.join('')

		const signature = signBlock({
			hash,
			secretKey: this.wallet.config.privateKey,
		})

		const ticket = btoa(
			JSON.stringify({
				...data,
				signature,
			}),
		)

		return ticket
	}

	async parseTicket(ticket: string) {
		const isValidBase64 =
			ticket.length % 4 === 0 && /^[A-Za-z0-9+/]+[=]{0,2}$/.test(ticket)

		if (!isValidBase64) {
			throw new Error('Invalid ticket')
		}

		let data

		try {
			data = JSON.parse(atob(ticket))
		} catch (err) {
			throw new Error('Invalid ticket')
		}

		const { ip, amount, version, expiresAt, verificationRequired, signature } =
			data

		if (version < 1) {
			throw new Error('Old ticket version')
		}

		const isValidIP = isValidIPv4OrIpv6(ip)

		if (
			!isValidIP ||
			!checkAmount(amount) ||
			!checkSignature(signature) ||
			typeof verificationRequired !== 'boolean'
		) {
			throw new Error('Invalid ticket')
		}

		const digest = await crypto.subtle.digest(
			{
				name: 'SHA-256',
			},
			new TextEncoder().encode(
				JSON.stringify({
					ip,
					amount,
					version,
					expiresAt,
					verificationRequired,
				}),
			),
		)

		const hash = [...new Uint8Array(digest)]
			.map(b => b.toString(16).padStart(2, '0'))
			.join('')

		const matchSignature = verifyBlock({
			hash,
			publicKey: this.wallet.publicKey,
			signature,
		})

		if (!matchSignature) {
			throw new Error('Invalid ticket')
		}

		return {
			ip,
			amount,
			version,
			expiresAt,
			hash,
			verificationRequired,
			signature,
		}
	}

	async checkProxy(ip: string) {
		const response = await fetch(`https://api.badip.info/${ip}?strategy=quick`)
		if (!response.ok) {
			throw new Error('Proxy check failed')
		}
		const data = await response.json<Record<string, any>>()
		if (!('isBad' in data)) {
			throw new Error('Proxy check failed')
		}
		return data.isBad as boolean
	}

	async redeemTicket({ hash, expiresAt }: { hash: string; expiresAt: number }) {
		const redeemedTicketHashes = await this.storage.get<Record<string, number>>(
			'redeemed_ticket_hashes',
		)

		const now = Date.now()
		const nonExpiredTickets = Object.entries(redeemedTicketHashes || {}).filter(
			([, expiresAt]) => expiresAt > now,
		)

		// save redeemed ticket hashes with expiresAt for later deletion
		await this.storage.put('redeemed_ticket_hashes', {
			...Object.fromEntries(nonExpiredTickets),
			[hash]: expiresAt,
		})
	}

	async saveDrop(data: {
		hash: string
		account: string
		amount: string
		ip: string
		timestamp: number
		took: number
	}) {
		const [dropsCount] = await this.db.batch<Record<string, any>>([
			this.db
				.prepare(
					'SELECT COUNT(*) as count FROM drops WHERE account = ?1 AND timestamp >= ?2',
				)
				.bind(data.account, Date.now() - PERIOD),
			this.db
				.prepare(
					'INSERT INTO drops (hash, account, amount, ip, timestamp, took) VALUES (?1, ?2, ?3, ?4, ?5, ?6)',
				)
				.bind(
					data.hash,
					data.account,
					data.amount,
					data.ip,
					data.timestamp,
					data.took,
				),
		])

		const count = dropsCount.results
			? (dropsCount.results[0].count as number)
			: 0

		if (count + 1 >= MAX_DROPS_PER_ACCOUNT) {
			const accountWhitelist =
				(await this.storage.get<string[]>('account-whitelist')) || []
			if (!accountWhitelist.includes(data.account)) {
				await this.addAccountToTmpBlacklist(data.account)
			}
		}
	}

	async enqueueIPTicket(ip: string, ticket: string): Promise<() => void> {
		if (!(ip in this.ipTicketQueue)) {
			this.ipTicketQueue[ip] = []
		}

		const promises = [...this.ipTicketQueue[ip]]

		if (promises.length === MAX_DROP_PER_IP_SIMULTANEOUSLY) {
			throw new HTTPException(403, { message: 'Many simultaneous requests' })
		}

		let resolve = () => {
			return
		}
		const promise = new Promise<void>(res => {
			resolve = () => res()
		})

		this.ipTicketQueue[ip].push(promise)

		await Promise.all(promises)

		return () => {
			resolve()
			this.ipTicketQueue[ip] = this.ipTicketQueue[ip].filter(p => p !== promise)
		}
	}

	async accountIsInTmpBlacklist(account: string) {
		const checksum = account.slice(-8)
		const blacklistedAccounts =
			(await this.storage.get<string[]>('temporary-account-blacklist')) || []
		if (blacklistedAccounts.includes(checksum)) return true
		return false
	}

	async addAccountToTmpBlacklist(account: string) {
		// Durable Objects applies a 128 KiB limit for storing values.
		// That's why it's preferable to just store the checksums for each account, since
		// the possibility of 2 accounts checksum having the same array is 1 in 32 ** 8.
		// MAX_TMP_ACCOUNT_BLACKLIST_LENGTH must ensure that the size of the serialized
		// array does not exceed the limit.

		const checksum = account.slice(-8)
		const blacklistedAccounts =
			(await this.storage.get<string[]>('temporary-account-blacklist')) || []
		if (blacklistedAccounts.includes(checksum)) return
		if (blacklistedAccounts.length === MAX_TMP_ACCOUNT_BLACKLIST_LENGTH) {
			blacklistedAccounts.shift()
		}
		blacklistedAccounts.push(checksum)
		await this.storage.put('temporary-account-blacklist', blacklistedAccounts)
	}

	fetch(request: Request) {
		return this.app.fetch(request)
	}
}
