import { useEffect, useState } from "react";
import AppLayout from "@/components/layout/AppLayout";
import MainHeader from "@/components/layout/MainHeader";
import CourseCard from "@/components/cards/CourseCard";
import LikeFavBar from "@/components/common/LikeFavBar";
import { knowpostService } from "@/services/knowpostService";
import AuthStatus from "@/features/auth/AuthStatus";
import styles from "./HomePage.module.css";

const HomePage = () => {
  const [items, setItems] = useState<Array<{
    id: string;
    title: string;
    description: string;
    coverImage?: string;
    tags: string[];
    tagJson?: string;
    authorAvatar?: string;
    authorAvator?: string;
    authorNickname: string;
    likeCount?: number;
    favoriteCount?: number;
    liked?: boolean;
    faved?: boolean;
  }>>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      setLoading(true);
      setError(null);
      try {
        const resp = await knowpostService.feed(1, 20);
        if (!cancelled) {
          setItems(resp.items ?? []);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : "加载失败";
        if (!cancelled) setError(msg);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    run();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <AppLayout
      header={
        <MainHeader
          headline="KnowFlow 知识社区"
          subtitle="发现高质量知识流，沉淀创作，也让 TitanX Agent 帮你整理灵感"
          rightSlot={<AuthStatus />}
        />
      }
    >
      {error ? <div>{error}</div> : null}
      <div className={styles.masonry}>
        {items.map(item => (
          <div key={item.id} className={styles.masonryItem}>
            <CourseCard
              id={item.id}
              title={item.title}
              summary={item.description ?? ""}
              tags={item.tags ?? []}
              authorTags={(() => {
                try {
                  return item.tagJson ? (JSON.parse(item.tagJson) as unknown[]).filter((t) => typeof t === "string") as string[] : [];
                } catch {
                  return [];
                }
              })()}
              teacher={{ name: item.authorNickname, avatarUrl: item.authorAvatar ?? item.authorAvator }}
              coverImage={item.coverImage}
                to={`/post/${item.id}`}
              footerExtra={<LikeFavBar entityId={item.id} compact initialCounts={{ like: item.likeCount ?? 0, fav: item.favoriteCount ?? 0 }} initialState={{ liked: item.liked, faved: item.faved }} />}
            />
          </div>
        ))}
        {loading ? <div className={styles.masonryItem}><div className={styles.stateCard}>正在加载知识流…</div></div> : null}
        {!loading && items.length === 0 ? (
          <div className={styles.masonryItem}><div className={styles.stateCard}>暂无内容，去发布第一篇知识吧</div></div>
        ) : null}
      </div>
    </AppLayout>
  );
};

export default HomePage;
