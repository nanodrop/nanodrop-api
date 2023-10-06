import { Hono } from 'hono'
import queue from './queue'
import { Bindings } from './types'
import { NanoDrop } from './nanodrop'

export { NanoDrop } from './nanodrop'

const app = new Hono<{ Bindings: Bindings }>()

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
	const id = c.env.DURABLE_OBJECT.idFromName(`nanodrop-${NanoDrop.version}`)
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
	queue,
}
