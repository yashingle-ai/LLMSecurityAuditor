// Embeddable chat widget for the Acme customer portal.
// Talks to the support agent's backend, which keeps the model API key on the server.
const CHAT_URL = "/chat";

export async function ask(question, sessionToken) {
  const response = await fetch(CHAT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${sessionToken}`,
    },
    body: JSON.stringify({ message: question }),
  });
  const data = await response.json();
  return data.reply;
}
