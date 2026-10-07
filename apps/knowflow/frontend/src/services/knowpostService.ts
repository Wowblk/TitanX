import { apiFetch } from "./apiClient";
import type {
  CreateDraftResponse,
  PresignRequest,
  PresignResponse,
  ConfirmContentRequest,
  UpdateKnowPostRequest,
  FeedResponse,
  DraftPageResponse,
  KnowpostDetailResponse,
  LikeActionResponse,
  FavActionResponse,
  CounterResponse,
  VisibleScope
} from "@/types/knowpost";

const KNOWPOST_PREFIX = "/api/v1/knowposts";
const STORAGE_PREFIX = "/api/v1/storage";

export const knowpostService = {
  createDraft: () =>
    apiFetch<CreateDraftResponse>(`${KNOWPOST_PREFIX}/drafts`, { method: "POST" }),

  presign: (payload: PresignRequest) =>
    apiFetch<PresignResponse>(`${STORAGE_PREFIX}/presign`, { method: "POST", body: payload }),

  confirmContent: (id: string, payload: ConfirmContentRequest) =>
    apiFetch<void>(`${KNOWPOST_PREFIX}/${id}/content/confirm`, { method: "POST", body: payload }),

  update: (id: string, payload: UpdateKnowPostRequest) =>
    apiFetch<void>(`${KNOWPOST_PREFIX}/${id}`, { method: "PATCH", body: payload }),

  publish: (id: string) =>
    apiFetch<void>(`${KNOWPOST_PREFIX}/${id}/publish`, { method: "POST" })
  ,
  
  // 设置置顶（需鉴权）
  setTop: (id: string, isTop: boolean, accessToken: string) =>
    apiFetch<void>(`${KNOWPOST_PREFIX}/${id}/top`, {
      method: "PATCH",
      body: { isTop },
      accessToken
    })
  ,

  // 设置可见性（需鉴权）
  setVisibility: (id: string, visible: VisibleScope, accessToken: string) =>
    apiFetch<void>(`${KNOWPOST_PREFIX}/${id}/visibility`, {
      method: "PATCH",
      body: { visible },
      accessToken
    })
  ,

  // 删除知文（需鉴权）
  remove: (id: string, accessToken: string) =>
    apiFetch<void>(`${KNOWPOST_PREFIX}/${id}`, {
      method: "DELETE",
      accessToken
    })
  ,

  // 获取首页 Feed 列表（公开内容）
  feed: (page = 1, size = 20) =>
    apiFetch<FeedResponse>(`${KNOWPOST_PREFIX}/feed?page=${page}&size=${size}`)
  ,

  // 获取我的知文（需鉴权）
  mine: (page = 1, size = 20, accessToken: string) =>
    apiFetch<FeedResponse>(`${KNOWPOST_PREFIX}/mine?page=${page}&size=${size}`, {
      accessToken
    })
  ,

  // 获取我的草稿（需鉴权）
  drafts: (page = 1, size = 20, accessToken: string) =>
    apiFetch<DraftPageResponse>(`${KNOWPOST_PREFIX}/drafts?page=${page}&size=${size}`, {
      accessToken
    })
  ,

  // 获取知文详情（公开内容无需鉴权；非公开需要作者凭证）
  detail: (id: string, accessToken?: string) =>
    apiFetch<KnowpostDetailResponse>(`${KNOWPOST_PREFIX}/detail/${id}`, {
      accessToken: accessToken ?? null
    })
  ,

  // 生成知文摘要（需鉴权）
  suggestDescription: (content: string, accessToken: string) =>
    apiFetch<{ description: string }>(`${KNOWPOST_PREFIX}/description/suggest`, {
      method: "POST",
      body: { content },
      accessToken
    })
  ,

  // 点赞/取消点赞（需鉴权）
  like: (entityId: string, accessToken: string, entityType: string = "knowpost") =>
    apiFetch<LikeActionResponse>(`/api/v1/action/like`, {
      method: "POST",
      body: { entityType, entityId },
      accessToken
    })
  ,
  unlike: (entityId: string, accessToken: string, entityType: string = "knowpost") =>
    apiFetch<LikeActionResponse>(`/api/v1/action/unlike`, {
      method: "POST",
      body: { entityType, entityId },
      accessToken
    })
  ,

  // 收藏/取消收藏（需鉴权）
  fav: (entityId: string, accessToken: string, entityType: string = "knowpost") =>
    apiFetch<FavActionResponse>(`/api/v1/action/fav`, {
      method: "POST",
      body: { entityType, entityId },
      accessToken
    })
  ,
  unfav: (entityId: string, accessToken: string, entityType: string = "knowpost") =>
    apiFetch<FavActionResponse>(`/api/v1/action/unfav`, {
      method: "POST",
      body: { entityType, entityId },
      accessToken
    })
  ,

  // 获取计数（需鉴权）
  counters: (entityId: string, accessToken: string, entityType: string = "knowpost") =>
    apiFetch<CounterResponse>(`/api/v1/counter/${entityType}/${entityId}?metrics=like,fav`, {
      accessToken
    })
};

/**
 * 直传到预签名 URL。注意：S3/OSS 会在响应头返回 ETag。
 */
export async function uploadToPresigned(putUrl: string, headers: Record<string, string>, file: File) {
  const uploadHeaders = { ...headers };
  if (putUrl.startsWith("/")) {
    try {
      const raw = localStorage.getItem("knowflow_auth_tokens");
      const token = raw ? (JSON.parse(raw) as { accessToken?: string }).accessToken : null;
      if (token) {
        uploadHeaders.Authorization = `Bearer ${token}`;
      }
    } catch {
      // 保持无 Authorization 头，由服务端返回鉴权错误。
    }
  }
  const resp = await fetch(putUrl, {
    method: "PUT",
    headers: uploadHeaders,
    body: file,
    // 跨域上传通常不需要携带凭据
    credentials: "omit"
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(text || `上传失败：${resp.status}`);
  }
  // ETag 常带双引号
  const etag = resp.headers.get("ETag") || resp.headers.get("etag") || "";
  return { etag };
}

export async function computeSha256(file: File) {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
  return hex;
}
