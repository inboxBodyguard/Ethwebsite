import { GatewayClient } from 'ai-gateway';

export default async function handler(req, res) {
  const gatewayKey = process.env.AI_GATEWAY_KEY;
  const { prompt } = req.body;

  const client = new GatewayClient({ apiKey: gatewayKey });

  const response = await client.complete({
    model: 'gpt-4o', // or switch to another model supported by AI Gateway
    prompt
  });

  res.status(200).json(response);
}