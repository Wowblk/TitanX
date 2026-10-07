export type CreateDraftResponse = {
  id: string;
};

export type PresignRequest = {
  scene: "knowpost_content" | "knowpost_image";
  postId: string;
  contentType: string;
  ext: string; // with dot, e.g. ".md" 
};

export type PresignResponse = {
  objectKey: string;
  putUrl: string;
  headers: Record<string, string>;
  expiresIn: number;
};

export type ConfirmContentRequest = {
  objectKey: string;
  etag: string;
  size: number;
  sha256: string;
};

export type VisibleScope = "public" | "followers" | "school" | "private" | "unlisted";

export type UpdateKnowPostRequest = {
  title?: string;
  tagId?: number;
  tags?: string[];
  imgUrls?: string[];
  visible?: VisibleScope;
  isTop?: boolean;
  description?: string;
};

// Feed 列表数据结构
export type FeedItem = {
  id: string;
  title: string;
  description: string;
  coverImage?: string;
  tags: string[];
  tagJson?: string;
  authorAvatar?: string; // 后端字段名为 authorAvatar
  authorAvator?: string; // 兼容历史拼写
  authorNickname: string;
  likeCount?: number;
  favoriteCount?: number;
  liked?: boolean;
  faved?: boolean;
  isTop?: boolean;
  visible?: VisibleScope;
};

export type FeedResponse = {
  items: FeedItem[];
  page: number;
  size: number;
  hasMore: boolean;
};

export type DraftItem = {
  id: string;
  title?: string;
  description?: string;
  contentUrl?: string;
  images: string[];
  tags: string[];
  visible: VisibleScope;
  type: "image_text" | string;
  createTime?: string;
  updateTime?: string;
};

export type DraftPageResponse = {
  items: DraftItem[];
  page: number;
  size: number;
  hasMore: boolean;
};

// 知文详情数据结构
export type KnowpostDetailResponse = {
  id: string;
  title: string;
  description: string;
  contentUrl: string;
  images: string[];
  tags: string[];
  authorAvatar?: string;
  authorNickname: string;
  authorId?: number;
  authorTagJson?: string;
  likeCount: number;
  favoriteCount: number;
  liked?: boolean;
  faved?: boolean;
  isTop: boolean;
  visible: "public" | "followers" | "school" | "private" | "unlisted";
  type: "image_text" | string;
  publishTime?: string;
};

// 点赞/取消点赞 响应
export type LikeActionResponse = {
  changed: boolean;
  liked: boolean;
};

// 收藏/取消收藏 响应
export type FavActionResponse = {
  changed: boolean;
  faved: boolean;
};

// 计数查询响应
export type CounterResponse = {
  entityType: string;
  entityId: string;
  counts: {
    like: number;
    fav: number;
  };
};
