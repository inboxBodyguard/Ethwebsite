import OpenAI from '@ai-sdk/openai';

export default async function handler(req, res) {
  const openaiKey = process.env.OPENAI_API_KEY;
  const { prompt } = req.body;

  const client = new OpenAI({ apiKey: openaiKey });

  const response = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }]
  });

  res.status(200).json(response);
}