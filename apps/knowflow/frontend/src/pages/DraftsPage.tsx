import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import AppLayout from "@/components/layout/AppLayout";
import MainHeader from "@/components/layout/MainHeader";
import AuthStatus from "@/features/auth/AuthStatus";
import SectionHeader from "@/components/common/SectionHeader";
import { useAuth } from "@/context/AuthContext";
import { knowpostService } from "@/services/knowpostService";
import type { DraftItem } from "@/types/knowpost";
import styles from "./DraftsPage.module.css";

const formatDate = (value?: string) => {
  if (!value) return "刚刚更新";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "刚刚更新";
  return date.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
};

const DraftsPage = () => {
  const { user, tokens } = useAuth();
  const [items, setItems] = useState<DraftItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      if (!tokens?.accessToken) return;
      setLoading(true);
      setError(null);
      try {
        const resp = await knowpostService.drafts(1, 30, tokens.accessToken);
        if (!cancelled) setItems(resp.items ?? []);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "草稿加载失败";
        if (!cancelled) setError(msg);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [tokens?.accessToken]);

  return (
    <AppLayout
      header={
        <MainHeader
          headline="我的草稿"
          subtitle="继续编辑未发布的 KnowFlow 内容，也能接住 TitanX Agent 创建的草稿"
          rightSlot={<AuthStatus />}
        />
      }
    >
      <section className={styles.panel}>
        <SectionHeader
          title="草稿箱"
          subtitle="保存后不会进入公开 Feed，发布后才会展示给其他用户"
          actions={<Link to="/create" className="ghost-button">新建创作</Link>}
        />
        {!user ? (
          <div className={styles.state}>请登录后查看你的草稿</div>
        ) : null}
        {error ? <div className={styles.error}>{error}</div> : null}
        {loading ? <div className={styles.state}>正在加载草稿…</div> : null}
        {!loading && user && items.length === 0 ? (
          <div className={styles.state}>暂无草稿，去创作或让 AI 帮你起草一篇</div>
        ) : null}
        <div className={styles.list}>
          {items.map(item => (
            <article key={item.id} className={styles.card}>
              <div className={styles.cardMain}>
                <div className={styles.cardHeader}>
                  <h2>{item.title?.trim() || "未命名草稿"}</h2>
                  <span>{formatDate(item.updateTime ?? item.createTime)}</span>
                </div>
                <p>{item.description?.trim() || "还没有摘要，继续编辑后可以补充内容说明。"}</p>
                <div className={styles.tags}>
                  {(item.tags ?? []).slice(0, 4).map(tag => <span key={tag}>#{tag}</span>)}
                  {item.visible === "private" ? <span>私密</span> : null}
                  {item.contentUrl ? <span>已保存正文</span> : null}
                </div>
              </div>
              {item.images?.[0] ? <img className={styles.cover} src={item.images[0]} alt="" /> : null}
              <Link className={styles.editButton} to={`/create?draftId=${item.id}`}>
                继续编辑
              </Link>
            </article>
          ))}
        </div>
      </section>
    </AppLayout>
  );
};

export default DraftsPage;
