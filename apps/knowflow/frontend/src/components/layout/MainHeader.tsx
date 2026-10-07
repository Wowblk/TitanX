import type { ReactNode } from "react";
import UserBadge from "@/components/common/UserBadge";
import styles from "./MainHeader.module.css";

export type HeaderTab = {
  id: string;
  label: string;
  badge?: ReactNode;
  active?: boolean;
  onSelect?: (id: string) => void;
};

export type MainHeaderProps = {
  headline: string;
  subtitle?: string;
  tabs?: HeaderTab[];
  filters?: HeaderTab[];
  rightSlot?: ReactNode;
  children?: ReactNode;
  user?: {
    name: string;
    alias?: string;
    avatarUrl?: string;
  };
};

const MainHeader = ({ headline, subtitle, tabs, filters, rightSlot, children, user }: MainHeaderProps) => {
  const renderTab = (tab: HeaderTab, variant: "tab" | "filter" = "tab") => {
    const className =
      variant === "tab"
        ? `${styles.tab} ${tab.active ? styles.tabActive : ""}`
        : `${styles.filterButton} ${tab.active ? styles.filterButtonActive : ""}`;

    return (
      <button
        key={tab.id}
        type="button"
        className={className}
        onClick={() => tab.onSelect?.(tab.id)}
      >
        {tab.label}
        {tab.badge ? <span>{tab.badge}</span> : null}
      </button>
    );
  };

  return (
    <header className={styles.header}>
      <div className={styles.topRow}>
        <div className={styles.titles}>
          <h1 className={styles.headline}>{headline}</h1>
          {subtitle ? <p className={styles.subtitle}>{subtitle}</p> : null}
        </div>
        <div className={styles.extras}>
          {rightSlot}
          {user ? <UserBadge name={user.name} alias={user.alias} avatarUrl={user.avatarUrl} /> : null}
        </div>
      </div>

      {tabs && tabs.length ? <div className={styles.tabs}>{tabs.map(tab => renderTab(tab, "tab"))}</div> : null}

      {filters && filters.length ? (
        <div className={styles.filters}>{filters.map(filter => renderTab(filter, "filter"))}</div>
      ) : null}

      {children}
    </header>
  );
};

export default MainHeader;
