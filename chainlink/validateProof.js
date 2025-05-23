// This validator randomly decides if the proof is valid

// Ensure args[0] exists and is a string
if (!args || args.length === 0 || typeof args[0] !== "string") {
  throw Error("Invalid arguments");
}

// Simulate randomness (not secure randomness, but good enough for a demo)
const rand = Math.random();

if (rand < 0.7) {
  return true; // 70% chance success
} else {
  throw Error("Proof validation failed randomly");
}
