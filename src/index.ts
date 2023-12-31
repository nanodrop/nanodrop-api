import { Hono } from 'hono'
import { Bindings } from './types'
import { NanoDrop } from './nanodrop'
import { deriveAddress, derivePublicKey } from 'nanocurrency'
import { errorHandler } from './middlewares'

export { NanoDrop } from './nanodrop'

const app = new Hono<{ Bindings: Bindings }>().onError(errorHandler)

app.options('*', c => {
	return c.text('', 204, {
		'Access-Control-Allow-Origin': c.env.ALLOW_ORIGIN
			? new URL(c.env.ALLOW_ORIGIN).origin
			: '*',
		'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type',
	})
})

app.use('*', async c => {
	const publicKey = derivePublicKey(c.env.PRIVATE_KEY)
	const account = deriveAddress(publicKey)

	const id = c.env.DURABLE_OBJECT.idFromName(
		`nanodrop-${NanoDrop.version}-${account}`,
	)

	const obj = c.env.DURABLE_OBJECT.get(id)

	const response = await obj.fetch(c.req.url, {
		method: c.req.method,
		headers: c.req.headers,
		body: c.req.body,
	})

	// Add Cors
	const headers = new Headers(response.headers)
	headers.set(
		'Access-Control-Allow-Origin',
		c.env.ALLOW_ORIGIN ? new URL(c.env.ALLOW_ORIGIN).origin : '*',
	)

	return new Response(response.body, {
		status: response.status,
		headers,
	})
})

export default {
	fetch: app.fetch,
}
