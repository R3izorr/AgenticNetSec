const phaseCards = [
  {
    title: "Ingestion",
    metric: "0 cases",
    detail: "PCAP intake queue and pre-check status",
  },
  {
    title: "Detection",
    metric: "No active alerts",
    detail: "Rule and heuristic signals from latest runs",
  },
  {
    title: "Reasoning",
    metric: "Awaiting reports",
    detail: "Forensic narrative and confidence summaries",
  },
  {
    title: "Reporting",
    metric: "outputs/",
    detail: "Structured artifacts and markdown briefs",
  },
];

const widgets = [
  {
    title: "Case Feed",
    body: "List recent analyses and quickly jump to investigation context.",
  },
  {
    title: "Evidence Timeline",
    body: "Plot key observations and inferred attack flow in chronological order.",
  },
  {
    title: "IOC Workspace",
    body: "Track suspicious hosts, ports, hashes, and operator notes in one place.",
  },
  {
    title: "Safety Gates",
    body: "Reserve space for confidence thresholds and human-review triggers.",
  },
];

export default function Home() {
  return (
    <div className="space-y-8">
      <section className="rounded-3xl border border-[var(--color-border)] bg-[var(--color-surface)] p-7 shadow-[0_18px_50px_-36px_rgba(14,165,233,0.45)]">
        <p className="font-mono text-xs uppercase tracking-[0.28em] text-[var(--color-accent)]">
          Starter Shell
        </p>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight text-[var(--color-text)] sm:text-4xl">
          Build your investigation workspace here.
        </h2>
        <p className="mt-4 max-w-3xl text-sm leading-7 text-[var(--color-text-muted)] sm:text-base">
          This frontend is intentionally scaffolded as a clean starting point for your
          forensic product flow. Add data wiring next, then plug in timeline,
          findings, and report-generation widgets.
        </p>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {phaseCards.map((card) => (
          <article
            key={card.title}
            className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-soft)] p-5"
          >
            <p className="text-xs uppercase tracking-[0.22em] text-[var(--color-text-muted)]">
              {card.title}
            </p>
            <p className="mt-3 text-lg font-semibold text-[var(--color-text)]">{card.metric}</p>
            <p className="mt-2 text-sm text-[var(--color-text-muted)]">{card.detail}</p>
          </article>
        ))}
      </section>

      <section className="grid gap-4 md:grid-cols-2">
        {widgets.map((widget) => (
          <article
            key={widget.title}
            className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6"
          >
            <h3 className="text-lg font-medium text-[var(--color-text)]">{widget.title}</h3>
            <p className="mt-3 text-sm leading-7 text-[var(--color-text-muted)]">{widget.body}</p>
          </article>
        ))}
      </section>
    </div>
  );
}
