import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { knowpostService } from "@/services/knowpostService";
import { HeartIcon, BookmarkIcon } from "@/components/icons/Icon";
import styles from "./LikeFavBar.module.css";

type LikeFavBarProps = {
  entityId: string;
  entityType?: string; // default: "knowpost"
  initialCounts?: { like: number; fav: number };
  initialState?: { liked?: boolean; faved?: boolean };
  fetchCounts?: boolean; // if true, fetch counts on mount (requires auth per current policy)
  compact?: boolean;
  className?: string;
};

const LikeFavBar = ({
  entityId,
  entityType = "knowpost",
  initialCounts,
  initialState,
  fetchCounts = false,
  compact = false,
  className
}: LikeFavBarProps) => {
  const { tokens } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const iconSize = compact ? 18 : 20;

  const [likeCount, setLikeCount] = useState<number>(initialCounts?.like ?? 0);
  const [favCount, setFavCount] = useState<number>(initialCounts?.fav ?? 0);
  const [liked, setLiked] = useState<boolean>(initialState?.liked ?? false);
  const [faved, setFaved] = useState<boolean>(initialState?.faved ?? false);
  const [loadingLike, setLoadingLike] = useState(false);
  const [loadingFav, setLoadingFav] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      if (!fetchCounts) return;
      if (!tokens?.accessToken) return; // 当前策略：需鉴权
      try {
        const resp = await knowpostService.counters(entityId, tokens.accessToken, entityType);
        if (!cancelled) {
          const like = resp.counts?.like ?? 0;
          const fav = resp.counts?.fav ?? 0;
          setLikeCount(typeof like === "number" ? like : 0);
          setFavCount(typeof fav === "number" ? fav : 0);
        }
      } catch {
        // 忽略计数加载错误，保持初值
      }
    };
    run();
    return () => { cancelled = true; };
  }, [entityId, entityType, tokens?.accessToken, fetchCounts]);

  // 当初始状态变更时，同步到本地状态（例如从详情或列表传入）
  useEffect(() => {
    if (typeof initialState?.liked !== "undefined") {
      setLiked(!!initialState.liked);
    }
    if (typeof initialState?.faved !== "undefined") {
      setFaved(!!initialState.faved);
    }
  }, [initialState?.liked, initialState?.faved]);

  const mustLogin = () => {
    navigate("/login", { state: { from: location.pathname } });
  };

  const onLikeClick = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation(); // 避免卡片 Link 导航
    if (!tokens?.accessToken) {
      mustLogin();
      return;
    }
    if (loadingLike) return;
    setLoadingLike(true);
    try {
      if (!liked) {
        const resp = await knowpostService.like(entityId, tokens.accessToken, entityType);
        setLiked(resp.liked);
        if (resp.changed && resp.liked) setLikeCount((c) => c + 1);
      } else {
        const resp = await knowpostService.unlike(entityId, tokens.accessToken, entityType);
        setLiked(resp.liked);
        if (resp.changed && !resp.liked) setLikeCount((c) => Math.max(0, c - 1));
      }
    } catch {
      // 可选：提示错误
    } finally {
      setLoadingLike(false);
    }
  };

  const onFavClick = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!tokens?.accessToken) {
      mustLogin();
      return;
    }
    if (loadingFav) return;
    setLoadingFav(true);
    try {
      if (!faved) {
        const resp = await knowpostService.fav(entityId, tokens.accessToken, entityType);
        setFaved(resp.faved);
        if (resp.changed && resp.faved) setFavCount((c) => c + 1);
      } else {
        const resp = await knowpostService.unfav(entityId, tokens.accessToken, entityType);
        setFaved(resp.faved);
        if (resp.changed && !resp.faved) setFavCount((c) => Math.max(0, c - 1));
      }
    } catch {
      // 可选：提示错误
    } finally {
      setLoadingFav(false);
    }
  };

  return (
    <div className={`${styles._bar} ${compact ? styles.compact : ""} ${className ?? ""}`.trim()}>
      <button
        type="button"
        className={`${styles.btn} ${liked ? styles.liked : ""} ${loadingLike ? styles.disabled : ""}`}
        onClick={onLikeClick}
        aria-pressed={liked}
        aria-label={liked ? "取消点赞" : "点赞"}
      >
        <HeartIcon width={iconSize} height={iconSize} />
        <span className={styles.count}>{likeCount}</span>
      </button>
      <button
        type="button"
        className={`${styles.btn} ${faved ? styles.faved : ""} ${loadingFav ? styles.disabled : ""}`}
        onClick={onFavClick}
        aria-pressed={faved}
        aria-label={faved ? "取消收藏" : "收藏"}
      >
        <BookmarkIcon width={iconSize} height={iconSize} />
        <span className={styles.count}>{favCount}</span>
      </button>
    </div>
  );
};

export default LikeFavBar;