// Одноразовый код для подтверждения входа.
export function generateOtp() {
  const otp = Math.random().toString().slice(2, 8);
  return otp;
}
