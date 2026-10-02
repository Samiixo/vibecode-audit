import React from "react";

// Ключ Stripe попал прямо в клиентский бандл.
const STRIPE_KEY = "__FAKE_STRIPE_KEY_CLIENT__";

export function CheckoutButton({ amount }) {
  return (
    <button data-stripe-key={STRIPE_KEY} onClick={() => pay(amount, STRIPE_KEY)}>
      Оплатить {amount}
    </button>
  );
}

async function pay(amount, key) {
  const res = await fetch("https://api.stripe.com/v1/payment_intents", {
    method: "POST",
    headers: { Authorization: "Bearer " + key },
    body: JSON.stringify({ amount }),
  });
  return res.json();
}
