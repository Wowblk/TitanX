import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import clsx from "clsx";
import { Link } from "react-router-dom";
import Tag from "@/components/common/Tag";
import { HeartIcon } from "@/components/icons/Icon";
import { useAuth } from "@/context/AuthContext";
import { knowpostService } from "@/services/knowpostService";
import type { KnowpostDetailResponse, VisibleScope } from "@/types/knowpost";
import styles from "./CourseCard.module.css";

const renderEmHighlightedText = (text: string): ReactNode => {
  if (!text.includes("<em")) return text;

  const parts: ReactNode[] = [];
  const re = /<em(?:\s[^>]*)?>(.*?)<\/em>/gis;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  while ((match = re.exec(text)) !== null) {
    const start = match.index;
    if (start > lastIndex) parts.push(text.slice(lastIndex, start));
    parts.push(<em key={`em-${key++}`}>{match[1]}</em>);
    lastIndex = start + match[0].length;
  }

  if (lastIndex < text.length) parts.push(text.slice(lastIndex));
  return parts.length ? <>{parts}</> : text;
};

export type CourseCardProps = {
  id: string;
  title: string;
  summary: string;
  tags: string[];
  authorTags?: string[];
  isFree?: boolean;
  isTop?: boolean;
  teacher: {
    name: string;
    avatarText?: string;
    avatarUrl?: string;
  };
  stats?: {
    likes: number;
    views: number;
  };
  coverImage?: string;
  layout?: "vertical" | "horizontal";
  showPlayBadge?: boolean;
  footerExtra?: ReactNode;
  to?: string;
  className?: string;
  editable?: boolean;
  onChanged?: (action: "top" | "visibility" | "delete", payload?: unknown) => void;
};

const CourseCard = ({
  id,
  title,
  summary,
  tags,
  authorTags,
  isFree = true,
  isTop,
  teacher,
  stats,
  coverImage,
  layout = "vertical",
  showPlayBadge,
  footerExtra,
  to,
  className,
  editable = false,
  onChanged
}: CourseCardProps) => {
  const { tokens } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [detail, setDetail] = useState<KnowpostDetailResponse | null>(null);
  const [menuLoading, setMenuLoading] = useState(false);
  const [menuError, setMenuError] = useState<string | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);

  const loadDetailIfNeeded = async (id: string) => {
    if (detail || menuLoading) return;
    try {
      setMenuLoading(true);
      const d = await knowpostService.detail(id, tokens?.accessToken ?? undefined);
      setDetail(d);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "加载详情失败";
      setMenuError(msg);
    } finally {
      setMenuLoading(false);
    }
  };

  const toggleMenu = async (id: string) => {
    const next = !menuOpen;
    setMenuOpen(next);
    if (next) {
      await loadDetailIfNeeded(id);
    }
  };

  // 点击卡片其他区域收起菜单
  useEffect(() => {
    if (!menuOpen) return;
    const onDocClick = (e: MouseEvent) => {
      const target = e.target as Node;
      const btn = buttonRef.current;
      const menu = menuRef.current;
      if (menu && menu.contains(target)) return;
      if (btn && btn.contains(target)) return;
      setMenuOpen(false);
    };
    document.addEventListener("mousedown", onDocClick, true);
    return () => document.removeEventListener("mousedown", onDocClick, true);
  }, [menuOpen]);

  const handleSetTop = async (id: string, isTop: boolean) => {
    try {
      if (!tokens?.accessToken) {
        setMenuError("请先登录");
        return;
      }
      setMenuLoading(true);
      await knowpostService.setTop(id, isTop, tokens.accessToken);
      setDetail(prev => prev ? { ...prev, isTop } : prev);
      setMenuOpen(false);
      onChanged?.("top", { isTop });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "设置置顶失败";
      setMenuError(msg);
    } finally {
      setMenuLoading(false);
    }
  };

  const handleSetVisibility = async (id: string, visible: VisibleScope) => {
    try {
      if (!tokens?.accessToken) {
        setMenuError("请先登录");
        return;
      }
      setMenuLoading(true);
      await knowpostService.setVisibility(id, visible, tokens.accessToken);
      setDetail(prev => prev ? { ...prev, visible } : prev);
      setMenuOpen(false);
      onChanged?.("visibility", { visible });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "设置可见性失败";
      setMenuError(msg);
    } finally {
      setMenuLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      if (!tokens?.accessToken) {
        setMenuError("请先登录");
        return;
      }
      if (!window.confirm("确认删除这篇知文吗？删除后不可恢复")) return;
      setMenuLoading(true);
      await knowpostService.remove(id, tokens.accessToken);
      setMenuOpen(false);
      onChanged?.("delete");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "删除失败";
      setMenuError(msg);
    } finally {
      setMenuLoading(false);
    }
  };

  const content = (
    <>
      {/* 取消免费标识展示，保持卡片简洁 */}
      {/* 图片置于卡片顶部，保持原始比例；播放标识覆盖在封面中央 */}
      {coverImage ? (
        <div className={styles.coverWrap}>
          <img className={styles.cover} src={coverImage} alt={title} loading="lazy" />
          {showPlayBadge ? (
            <div className={styles.playBadge}>
              <svg width="24" height="24" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <polygon points="6,4 12,8 6,12" fill="currentColor" />
              </svg>
            </div>
          ) : null}
        </div>
      ) : null}

      <div className={styles.content}>
        <h3 className={styles.title}>{title}</h3>
        {summary.trim() ? (
          <p className={styles.description}>{renderEmHighlightedText(summary)}</p>
        ) : null}
        {tags?.length ? (
          <div className={styles.tagGroups}>
            {tags.map(tag => (
              <Tag key={tag}>#{tag}</Tag>
            ))}
          </div>
        ) : null}
      </div>

      <div className={styles.meta}>
        <div className={styles.teacher}>
          {teacher.avatarUrl ? (
            <img className={styles.teacherAvatarImg} src={teacher.avatarUrl} alt={teacher.name} />
          ) : (
            <div className={styles.teacherAvatar}>{teacher.avatarText ?? (teacher.name?.charAt(0) || "?")}</div>
          )}
          <div className={styles.teacherInfo}>
            <span className={styles.teacherName}>{teacher.name}</span>
            {authorTags?.length ? (
              <div className={styles.authorTags}>
                {authorTags.map(tag => (
                  <span key={tag} className={styles.authorTag}>#{tag}</span>
                ))}
              </div>
            ) : null}
          </div>
        </div>
        {footerExtra ? null : (
          <div className={styles.stats}>
            {stats ? (
              <>
                <span className={styles.statItem}>
                  <HeartIcon width={16} height={16} strokeWidth={1.6} />
                  {stats.likes}
                </span>
                <span className={styles.statItem}>👁️ {stats.views}</span>
              </>
            ) : null}
          </div>
        )}
      </div>

      {footerExtra ? (
        <div className={styles.footerExtra}>{footerExtra}</div>
      ) : null}
    </>
  );

  return (
    <article className={clsx(styles.card, className)}>
      {(detail?.isTop ?? isTop) ? (
        <div className={styles.topBadge}><span>置顶</span></div>
      ) : null}
      {editable ? (
        <>
          <button ref={buttonRef} type="button" className={styles.menuButton} onClick={() => toggleMenu(id)} aria-haspopup="true" aria-expanded={menuOpen} title="编辑">
            ⋯
          </button>
          {menuOpen ? (
            <div ref={menuRef} className={styles.menuList} role="menu">
              {menuError ? <div style={{ color: "var(--color-danger)", padding: 6 }}>{menuError}</div> : null}
              <button type="button" className={styles.menuItem} onClick={() => handleSetTop(id, !(detail?.isTop))} disabled={menuLoading}>
                {detail?.isTop ? "取消置顶" : "置顶"}
              </button>
              <button type="button" className={styles.menuItem} onClick={() => handleSetVisibility(id, "public")} disabled={menuLoading}>
                设为公开
              </button>
              <button type="button" className={styles.menuItem} onClick={() => handleSetVisibility(id, "private")} disabled={menuLoading}>
                设为私密
              </button>
              <button type="button" className={clsx(styles.menuItem, styles.menuDanger)} onClick={() => handleDelete(id)} disabled={menuLoading}>
                删除
              </button>
            </div>
          ) : null}
        </>
      ) : null}
      {to ? <Link to={to}>{content}</Link> : content}
    </article>
  );
};

export default CourseCard;
