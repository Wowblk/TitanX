import type { ReactNode } from "react";
import Sidebar from "./Sidebar";
import AgentAssistant from "@/features/agent/AgentAssistant";
import styles from "./AppLayout.module.css";

type AppLayoutProps = {
  header?: ReactNode;
  children: ReactNode;
  variant?: "default" | "cardless";
};

const AppLayout = ({ header, children, variant = "default" }: AppLayoutProps) => {
  return (
    <div className="app-shell">
      <Sidebar />
      <div className={styles.container}>
        {header}
        <div className={variant === "default" ? styles.pageCard : styles.main}>{children}</div>
      </div>
      <AgentAssistant />
    </div>
  );
};

export default AppLayout;
