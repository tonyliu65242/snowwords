require('dotenv').config();

const Groq = require('groq-sdk');

const groq = new Groq({
    apiKey: process.env.GROQ_API_KEY
});

// Model is configurable via env var so a future Groq decommission is a
// one-line change. Default: openai/gpt-oss-120b (Groq's recommended
// replacement for the now-decommissioned llama-3.3-70b-versatile).
const GROQ_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-120b';

async function sendToGemini(message, systemContext = null) {
    try {
        // Build messages array
        const messages = [];

        // Add system context if provided
        if (systemContext) {
            messages.push({
                role: "system",
                content: systemContext
            });
        }

        // Add user message
        messages.push({
            role: "user",
            content: message
        });

        // Call Groq API (model configurable via GROQ_MODEL env var)
        const completion = await groq.chat.completions.create({
            model: GROQ_MODEL,
            messages: messages,
            temperature: 0.7,
            max_tokens: 1024
        });

        if (!completion.choices || !completion.choices[0]) {
            throw new Error('No response from Groq API');
        }

        return completion.choices[0].message.content;
    } catch (error) {
        console.error('Groq API Error Details:', {
            message: error.message,
            status: error.status,
            statusText: error.statusText,
            response: error.response
        });

        // Provide more specific error messages
        if (error.message.includes('API key') || error.message.includes('Unauthorized')) {
            throw new Error('Invalid or missing Groq API key. Please check your GROQ_API_KEY environment variable.');
        } else if (error.message.includes('quota') || error.message.includes('rate limit')) {
            throw new Error('Groq API rate limit reached. Please try again in a moment.');
        } else {
            throw new Error(`Groq API error: ${error.message}`);
        }
    }
}

module.exports = { sendToGemini };