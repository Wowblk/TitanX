import clsx from "clsx";
import styles from "./Tag.module.css";

type TagProps = {
  children: React.ReactNode;
  tone?: "primary" | "success" | "neutral";
};

const Tag = ({ children, tone = "primary" }: TagProps) => {
  const tagClass = clsx(styles.tag, {
    [styles.toneSuccess]: tone === "success",
    [styles.toneNeutral]: tone === "neutral"
  });

  return <span className={tagClass}>{children}</span>;
};

export default Tag;
