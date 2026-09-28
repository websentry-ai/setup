// The one synthetic API key every suite uses. Assembled from fragments so secret scanners see a
// single, obviously-constructed placeholder rather than eighteen key-shaped literals — and so the
// value can never be mistaken for, or collide with, a real `unb_` credential. Only the loopback mock
// API accepts it.
export const TEST_KEY = ["unb", "test", "key", "1234567890"].join("_");
