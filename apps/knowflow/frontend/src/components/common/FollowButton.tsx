import { useEffect, useState } from "react";
import { relationService } from "@/services/relationService";
import { useAuth } from "@/context/AuthContext";
import styles from "./FollowButton.module.css";

type FollowButtonProps = {
  targetUserId?: number; // 若无则不展示
  compact?: boolean;
};

const FollowButton = ({ targetUserId, compact }: FollowButtonProps) => {
  const { tokens } = useAuth();
  const [loading, setLoading] = useState(false);
  const [following, setFollowing] = useState(false);
  const [mutual, setMutual] = useState(false);

  useEffect(() => {
    const run = async () => {
      if (!targetUserId || !tokens?.accessToken) return;
      try {
        const s = await relationService.status(targetUserId, tokens.accessToken);
        setFollowing(s.following);
        setMutual(s.mutual);
      } catch (e) {
        // 静默失败
      }
    };
    run();
  }, [targetUserId, tokens?.accessToken]);

  if (!targetUserId) return null;
  // 未登录不显示关注按钮
  if (!tokens?.accessToken) return null;

  const onClick = async () => {
    if (!tokens?.accessToken) return;
    setLoading(true);
    try {
      if (following) {
        await relationService.unfollow(targetUserId, tokens.accessToken);
        setFollowing(false);
        setMutual(false);
      } else {
        await relationService.follow(targetUserId, tokens.accessToken);
        setFollowing(true);
        // 互相关注状态需重新拉取或由后端返回，这里暂不推断
        try {
          const s = await relationService.status(targetUserId, tokens.accessToken);
          setMutual(s.mutual);
        } catch {}
      }
    } finally {
      setLoading(false);
    }
  };

  const className = `${styles.btn} ${following ? styles.following : ""}`;
  const label = following ? "已关注" : "关注";

  return (
    <button type="button" className={className} onClick={onClick} disabled={loading} aria-pressed={following}>
      <svg className={styles.icon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {following ? (
          <path d="M20 6L9 17l-5-5" />
        ) : (
          <path d="M12 5v14M5 12h14" />
        )}
      </svg>
      {label}
      {mutual ? <span className={styles.mutualBadge}>互关</span> : null}
    </button>
  );
};

export default FollowButton;