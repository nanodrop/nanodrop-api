import { Bindings } from "./types"

interface MessageBody { }

export default async function queue(batch: MessageBatch<MessageBody>, env: Bindings, ctx: ExecutionContext): Promise<void> {

    // Optional, otherwise process each message with a iterator
    if (batch.messages.length > 1) {
        console.error("Cannot process more than one message at a time");
        return
    }

    const queue = batch.queue;
    const body: MessageBody = batch.messages[0].body;

    switch (queue) {
        case "save-drop":
            console.log(JSON.stringify(body));
            break;
        default:
            console.error("Unknown queue: ", batch.queue);
    }
}