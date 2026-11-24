import { motion } from "motion/react";
import { Bug, Fingerprint, Gavel, LockKey, Package, TreeStructure } from "@phosphor-icons/react";
import type { Route } from "../route";
import { ease, rise, stagger } from "../ui";
import { RecentScans, useScans } from "./RecentScans";
import { DemoRepositories } from "./DemoRepositories";
import { SourceInput } from "./SourceInput";
import { useMeta } from "../useRun";

const WHAT = [
  { Icon: Package, t: "Every component", d: "manifests, lockfiles, build files, vendored code" },
  { Icon: TreeStructure, t: "SBOM + graph", d: "CycloneDX, SPDX and the full dependency tree" },
  { Icon: Bug, t: "Known vulnerabilities", d: "OSV.dev and Grype, with reachability" },
  { Icon: Fingerprint, t: "Suspicious changes", d: "typosquats, install scripts, registry redirects" },
  { Icon: Gavel, t: "A verdict with evidence", d: "risk scores and policy-as-code" },
];

/** Home: choose a source and scan it. Finished and running scans are listed underneath. */
export function Home({ go }: { go: (r: Route) => void }) {
  const { entries } = useScans();
  const meta = useMeta();
  const open = (id: string) => go({ page: "scan", id, view: "overview" });
  const started = (id: string, investigation: boolean) => investigation ? go({ page: "investigate", id }) : open(id);
  return (
    <motion.div initial="initial" animate="animate" variants={stagger(0.08)} className="mx-auto flex w-full max-w-5xl flex-col gap-10 pb-16 pt-6 md:pt-12">
      <motion.div variants={rise} className="flex flex-col items-center gap-4 text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/8 px-3 py-1 text-[12px] text-accent">
          <LockKey size={13} weight="bold" /> Pre-merge supply-chain check · nothing from your project is ever run
        </span>
        <h1 className="max-w-3xl text-balance text-4xl font-semibold tracking-tight md:text-5xl">
          Know what you build.{" "}
          <span className="bg-gradient-to-r from-accent via-[#7aa8ff] to-[#a78bfa] bg-clip-text text-transparent">Trust what you ship.</span>
        </h1>
        <p className="max-w-2xl text-pretty text-[15px] leading-relaxed text-muted">
          Point Guardian at a repository, a ZIP or a folder. It inventories everything the app is built from, finds known vulnerabilities and
          suspicious changes, and tells you what is new in this change, with the evidence behind every finding.
        </p>
      </motion.div>

      <motion.section variants={rise} className="panel relative overflow-hidden p-5 md:p-7">
        <motion.div aria-hidden className="pointer-events-none absolute -right-24 -top-24 size-72 rounded-full bg-accent/10 blur-3xl"
          animate={{ scale: [1, 1.15, 1], opacity: [0.6, 1, 0.6] }} transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }} />
        <SourceInput id="home" autoFocus investigate={meta?.live_available} allowScanOnly onStarted={started} />
      </motion.section>

      <motion.div variants={rise}><DemoRepositories investigate={!!meta?.live_available} onStarted={started} /></motion.div>

      <motion.ul variants={stagger(0.06, 0.15)} className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {WHAT.map(({ Icon, t, d }) => (
          <motion.li key={t} variants={{ initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0, transition: { duration: 0.5, ease } } }}
            className="flex flex-col gap-1.5 rounded-xl border border-line bg-surface/50 px-3.5 py-3">
            <Icon size={18} weight="duotone" className="text-accent" />
            <span className="text-[13px] font-medium">{t}</span>
            <span className="text-[11.5px] leading-snug text-muted">{d}</span>
          </motion.li>
        ))}
      </motion.ul>

      {entries.length > 0 && (
        <motion.section variants={rise} className="flex flex-col gap-3">
          <div className="flex items-baseline justify-between">
            <h2 className="text-[15px] font-medium">Recent scans</h2>
            <span className="text-[12px] text-faint">open one to see its report, graph, scores and fixes</span>
          </div>
          <RecentScans entries={entries} onOpen={open} />
        </motion.section>
      )}
    </motion.div>
  );
}
