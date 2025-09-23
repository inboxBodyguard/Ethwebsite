import { streamText } from 'ai';
import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

export default async function handler(req, res) {
  const { messages } = await req.body;

  const result = await streamText({
    model: client.chat.completions,
    messages,
  });

  res.setHeader('Content-Type', 'text/event-stream');
  for await (const delta of result.textStream) {
    res.write(delta);
  }
  res.end();
}