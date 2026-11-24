import { DepGraph } from "../components/DepGraph";
import { Badge, SectionHead, type Sections } from "./shared";

export function Discover({ s, project }: { s: Sections; project: string | null }) {
  const sboms = s.inventory?.sboms ?? {};
  return (
    <div className="flex flex-col gap-4">
      <SectionHead n={1} title="Discover what you build" sub="Every component is read from lockfiles and manifests (nothing from the repository is executed), cross-checked against Syft, and linked into a dependency graph. Pick a view, search a package, click it to see how it reaches the app."
        right={<span className="flex flex-wrap items-center gap-2 text-[11.5px] text-muted"><Badge kind="fact" />{Object.keys(sboms).length ? Object.keys(sboms).map((k) => <span key={k} className="rounded bg-raised px-1.5 py-0.5 font-mono text-[10.5px]">{k}</span>) : "SBOMs: CycloneDX + SPDX"}</span>} />
      <DepGraph project={project} />
    </div>);
}
