// Embeddable chat widget for the Acme customer portal.
// Calls the model API straight from the browser to save a round trip.
const MODEL_API_URL = "https://api.acme-llm.example/v1/chat/completions";
const MODEL_API_KEY = "acme_live_Q3xT8pLw2NvR6mYk1HsBd9Zc";

export async function ask(question) {
  const response = await fetch(MODEL_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${MODEL_API_KEY}`,
    },
    body: JSON.stringify({ model: "acme-support", messages: [{ role: "user", content: question }] }),
  });
  const data = await response.json();
  return data.choices[0].message.content;
}
