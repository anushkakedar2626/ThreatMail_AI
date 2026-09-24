import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ThreatMail AI — AI Email Forensic Intelligence Console" },
      {
        name: "description",
        content:
          "ThreatMail AI SOC console for email forensics: detect, investigate, correlate and explain phishing cases with risk scoring, threat graphs and observed sending infrastructure.",
      },
      { property: "og:title", content: "ThreatMail AI — AI Email Forensic Intelligence Console" },
      {
        property: "og:description",
        content:
          "Professional email forensics workspace: risk breakdown, threat relationship graph, investigation timeline, threat intelligence and reports.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

function Index() {
  return (
    <iframe
      src="/sentinelx.html"
      title="ThreatMail AI forensic console"
      style={{
        position: "fixed",
        inset: 0,
        width: "100%",
        height: "100%",
        border: 0,
      }}
    />
  );
}
