export const getBaseUrl = () => {
  const envBase = import.meta.env.VITE_API_BASE_URL as string | undefined;
  // 默认使用相对路径，配合 Vite dev proxy，在生产通过环境变量显式配置。
  return envBase?.replace(/\/$/, "") ?? "";
};

export type ApiFetchOptions = {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  accessToken?: string | null;
  signal?: AbortSignal;
};

export class ApiError extends Error {
  readonly status: number;
  readonly data: unknown;

  constructor(status: number, message: string, data: unknown) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

export async function apiFetch<TResponse>(path: string, options: ApiFetchOptions = {}): Promise<TResponse> {
  const baseUrl = getBaseUrl();
  const { method = "GET", headers = {}, body, accessToken, signal } = options;

  const isFormData = typeof FormData !== "undefined" && body instanceof FormData;

  const getStoredAccessToken = (): string | null => {
    if (typeof window === "undefined") return null;
    try {
      const raw = localStorage.getItem("knowflow_auth_tokens");
      if (!raw) return null;
      const parsed = JSON.parse(raw) as { accessToken?: string };
      return parsed.accessToken ?? null;
    } catch {
      return null;
    }
  };

  const mergedHeaders: Record<string, string> = {
    ...(isFormData ? {} : { "Content-Type": "application/json" }),
    ...headers
  };

  // 注意：当 accessToken 显式传入 null 时，表示不要附带 Authorization 头；
  // 只有当 accessToken 为 undefined（未指定）时，才从本地存储回退读取。
  const token = accessToken === undefined ? getStoredAccessToken() : accessToken;
  if (token) {
    mergedHeaders.Authorization = `Bearer ${token}`;
  }

  // 若服务端启用了 CSRF 防护（如 Spring Security），尝试从 Cookie 中读取 XSRF-TOKEN 并随非幂等请求附加到头部
  const methodUpper = method.toUpperCase();
  const isIdempotent = methodUpper === "GET" || methodUpper === "HEAD" || methodUpper === "OPTIONS";
  if (!isIdempotent && typeof document !== "undefined") {
    try {
      const cookies = document.cookie ?? "";
      const match = cookies.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
      const xsrfToken = match ? decodeURIComponent(match[1]) : null;
      if (xsrfToken && !("X-XSRF-TOKEN" in mergedHeaders)) {
        mergedHeaders["X-XSRF-TOKEN"] = xsrfToken;
      }
    } catch {
      // 忽略读取失败，保持无 header
    }
  }

  const url = baseUrl ? `${baseUrl}${path}` : path;
  const response = await fetch(url, {
    method,
    headers: mergedHeaders,
    body: isFormData ? (body as FormData) : body ? JSON.stringify(body) : undefined,
    signal,
    // 确保在代理或跨域场景下也能携带 Cookie（包括可能的 XSRF-TOKEN）
    credentials: "include"
  });

  if (!response.ok) {
    // 统一按文本读取一次，避免重复读取导致“body stream already read”
    let rawText = "";
    try {
      rawText = await response.text();
    } catch {
      rawText = "";
    }
    let errorData: unknown = rawText;
    if (rawText) {
      try {
        errorData = JSON.parse(rawText);
      } catch {
        // 保留原始文本
      }
    }
    const message = typeof errorData === "object" && errorData !== null && "message" in errorData
      ? (errorData as { message: string }).message
      : rawText || `请求失败：${response.status}`;
    throw new ApiError(response.status, message, errorData);
  }

  if (response.status === 204) {
    return undefined as TResponse;
  }

  const contentType = response.headers.get("content-type");
  if (contentType?.includes("application/json")) {
    return (await response.json()) as TResponse;
  }

  return (await response.text()) as TResponse;
}
