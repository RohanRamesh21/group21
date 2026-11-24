import { AnimatePresence, MotionConfig, motion } from "motion/react";
import { Home } from "./components/Home";
import { Investigate } from "./components/Investigate";
import { ScanPage } from "./components/ScanPage";
import { TopBar } from "./components/TopBar";
import { useRoute } from "./route";
import { pageMotion } from "./ui";
import { useMeta } from "./useRun";

/** Two pages: Scan (home → live pipeline → results) and Investigate (agents on any scan). */
export default function App() {
  const [route, go] = useRoute();
  const meta = useMeta();
  const key = route.page === "scan" ? `scan-${route.id}` : route.page === "investigate" ? `inv-${route.id ?? ""}` : "home";
  return (
    <MotionConfig reducedMotion="user">
      <div className="relative z-10 flex min-h-[100dvh] flex-col">
        <TopBar route={route} go={go} meta={meta} />
        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 pt-5 md:px-6">
          <AnimatePresence mode="wait">
            <motion.div key={key} {...pageMotion}>
              {route.page === "home" && <Home go={go} />}
              {route.page === "scan" && <ScanPage id={route.id} view={route.view} go={go} />}
              {route.page === "investigate" && <Investigate id={route.id} go={go} />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </MotionConfig>
  );
}
