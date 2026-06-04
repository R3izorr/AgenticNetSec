export type OrganizationRole = "owner" | "analyst" | "viewer" | string | null | undefined

export function canCreateAnalysis(role: OrganizationRole): boolean {
  return role === "owner" || role === "analyst"
}

export function canReadAnalysis(role: OrganizationRole): boolean {
  return role === "owner" || role === "analyst" || role === "viewer"
}
