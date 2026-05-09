export const PROVIDERS = ["google", "apple"] as const;
export type Provider = (typeof PROVIDERS)[number];
