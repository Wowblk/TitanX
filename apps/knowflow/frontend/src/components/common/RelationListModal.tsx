import { useEffect, useMemo, useState } from "react";
import styles from "./RelationListModal.module.css";
import { relationService } from "@/services/relationService";
import { useAuth } from "@/context/AuthContext";
import type { ProfileResponse } from "@/types/profile";

type Mode = "following" | "followers";

type RelationListModalProps = {
  open: boolean;
  onClose: () => void;
  userId: number;
  mode: Mode;
};

const initialLimit = 20;

const initialChar = (name?: string, id?: number) =>
  (name?.trim().charAt(0).toUpperCase() || String(id ?? "").trim().charAt(0).toUpperCase() || "?");

const RelationListModal = ({ open, onClose, userId, mode }: RelationListModalProps) => {
  const title = useMemo(() => (mode === "following" ? "关注列表" : "粉丝列表"), [mode]);
  const { tokens } = useAuth();
  const [profiles, setProfiles] = useState<ProfileResponse[]>([]);
  const [offset, setOffset] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState<boolean>(true);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    const run = async () => {
      if (!tokens?.accessToken) {
        setError("请登录后查看列表");
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const resp = mode === "following"
          ? await relationService.following(userId, initialLimit, 0, undefined, tokens.accessToken)
          : await relationService.followers(userId, initialLimit, 0, undefined, tokens.accessToken);
        if (cancelled) return;
        const list = Array.isArray(resp) ? resp : [];
        setProfiles(list);
        setOffset(list.length);
        setHasMore(list.length >= initialLimit);
      } catch (e) {
        const msg = e instanceof Error ? e.message : "加载失败";
        if (!cancelled) setError(msg);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    run();
    return () => { cancelled = true; };
  }, [open, userId, mode, tokens?.accessToken]);

  const loadMore = async () => {
    if (loading || !hasMore) return;
    if (!tokens?.accessToken) {
      setError("请登录后查看列表");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const resp = mode === "following"
        ? await relationService.following(userId, initialLimit, offset, undefined, tokens.accessToken)
        : await relationService.followers(userId, initialLimit, offset, undefined, tokens.accessToken);
      const list = Array.isArray(resp) ? resp : [];
      setProfiles(prev => [...prev, ...list]);
      setOffset(prev => prev + list.length);
      setHasMore(list.length >= initialLimit);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "加载失败";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  if (!open) return null;

  return (
    <div className={styles._overlay_1q1ln_1} onClick={onClose}>
      <div className={styles._modal_1q1ln_12} onClick={e => e.stopPropagation()}>
        <div className={styles._header_1q1ln_24}>
          <span className={styles._title_1q1ln_32}>{title}</span>
          <button className={styles._close_1q1ln_38} onClick={onClose}>关闭</button>
        </div>
        <div className={styles._body_1q1ln_46}>
          {error ? <div className={styles._error_1q1ln_106}>{error}</div> : null}
          {profiles.length === 0 && !loading ? (
            <div className={styles._empty_1q1ln_101}>暂无数据</div>
          ) : (
            <div className={styles._list_1q1ln_52}>
              {profiles.map((p) => (
                <div key={p.id} className={styles._item_1q1ln_59}>
                  {p.avatar ? (
                    <img className={styles._avatar_1q1ln_69} src={p.avatar} alt={p.nickname} />
                  ) : (
                    <div className={styles._avatar_1q1ln_69}>{initialChar(p.nickname, p.id)}</div>
                  )}
                  <div className={styles._name_1q1ln_80}>{p.nickname || "KnowFlow 用户"}</div>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className={styles._footer_1q1ln_85}>
          <button className={styles._more_1q1ln_93} onClick={loadMore} disabled={!hasMore || loading}>
            {loading ? "加载中..." : hasMore ? "加载更多" : "没有更多"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default RelationListModal;
