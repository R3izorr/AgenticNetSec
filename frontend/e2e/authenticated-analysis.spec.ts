import { expect, test, type Page } from "@playwright/test"
import fs from "node:fs"
import path from "node:path"

const apiURL = process.env.E2E_API_URL ?? "http://localhost:8000"
const defaultPcapPath = path.resolve(
  process.cwd(),
  "..",
  "pcap",
  "CredAccess",
  "DCSync_krbtgt_dcerpc_smb.pcapng"
)
const pcapPath = process.env.E2E_PCAP_PATH
  ? path.resolve(process.env.E2E_PCAP_PATH)
  : defaultPcapPath

async function apiFetch<T>(page: Page, route: string): Promise<{ status: number; body: T }> {
  return page.evaluate(
    async ({ apiURL, route }) => {
      const response = await fetch(`${apiURL}${route}`, { credentials: "include" })
      const text = await response.text()
      let body: unknown = null
      try {
        body = text ? JSON.parse(text) : null
      } catch {
        body = text
      }
      return { status: response.status, body }
    },
    { apiURL, route }
  ) as Promise<{ status: number; body: T }>
}

test("registered user can upload a PCAP, open report after refresh, and logout", async ({ page }) => {
  expect(fs.existsSync(pcapPath), `PCAP fixture not found: ${pcapPath}`).toBeTruthy()

  const email = `owner+e2e-${Date.now()}@example.test`
  const password = "Password123!"

  await page.goto("/register")
  await page.getByLabel("Display name").fill("Owner E2E")
  await page.getByLabel("Email").fill(email)
  await page.getByLabel("Password").fill(password)
  await page.getByRole("button", { name: "Create account" }).click()
  await page.waitForURL("**/dashboard")

  const me = await apiFetch<{ user?: { email?: string } }>(page, "/api/v1/auth/me")
  expect(me.status).toBe(200)
  expect(me.body.user?.email).toBe(email)

  await page.goto("/analysis/new")
  await page.setInputFiles("#pcap-files", pcapPath)
  await page.getByRole("button", { name: "Start Batch" }).click()
  await page.waitForURL("**/total-jobs/total_*")
  await expect(page.getByText("Total Job").first()).toBeVisible()

  const totalJobId = page.url().split("/").pop()
  expect(totalJobId).toMatch(/^total_/)

  let totalJob: {
    status?: string
    children?: Array<{ analysis_job_id?: string; analysisJobId?: string }>
  } | null = null

  for (let attempt = 0; attempt < 90; attempt += 1) {
    const response = await apiFetch<typeof totalJob>(page, `/api/v1/total-jobs/${totalJobId}`)
    expect(response.status).toBe(200)
    totalJob = response.body
    if (totalJob?.status === "completed") {
      break
    }
    expect(totalJob?.status).not.toBe("failed")
    await page.waitForTimeout(1000)
  }

  expect(totalJob?.status).toBe("completed")
  const child = totalJob?.children?.[0]
  const analysisJobId = child?.analysis_job_id ?? child?.analysisJobId
  expect(analysisJobId).toMatch(/^analysis_/)

  const report = await apiFetch<{ header?: unknown }>(page, `/api/v1/analysis/${analysisJobId}/report.json`)
  expect(report.status).toBe(200)
  expect(report.body.header).toBeTruthy()

  await page.goto(`/analysis/${analysisJobId}/report`)
  await expect(page.getByText("Analyst Summary")).toBeVisible()

  await page.reload()
  await expect(page.getByText("Analyst Summary")).toBeVisible()

  await page.getByLabel("Log out").click()
  await page.waitForURL("**/login**")

  await page.goto("/dashboard")
  await page.waitForURL("**/login?next=%2Fdashboard")
})
