export type IdentifierType = "PHONE" | "EMAIL" | "USERNAME";

export type VerificationScene = "REGISTER" | "LOGIN" | "RESET_PASSWORD";

export type SendCodeRequest = {
  scene: VerificationScene;
  identifierType: IdentifierType;
  identifier: string;
};

export type SendCodeResponse = {
  identifier: string;
  scene: VerificationScene;
  expireSeconds: number;
};

export type RegisterRequest = {
  identifierType: IdentifierType;
  identifier: string;
  code: string;
  password: string;
  agreeTerms: boolean;
};

// 与后端保持一致：登录/注册返回 AuthResponse，包含用户信息与令牌
import type { Gender } from "@/types/profile";

export type AuthUserResponse = {
  id: number;
  nickname: string;
  avatar: string;
  phone: string;
  email?: string;
  // 新增字段，与后端 auth/me 响应保持一致
  zhId?: string;
  birthday?: string; // LocalDate → 期望 yyyy-MM-dd 字符串
  school?: string;
  bio?: string;
  gender?: Gender; // "MALE" | "FEMALE" | "OTHER" | "UNKNOWN"
  // 兼容可能的扩展
  skills?: string[];
  // 后端可能返回的 JSON 字符串形式的标签
  tagJson?: string;
};

export type TokenResponse = {
  accessToken: string;
  accessTokenExpiresAt: string; // Instant → ISO 字符串
  refreshToken: string;
  refreshTokenExpiresAt: string; // Instant → ISO 字符串
};

export type AuthResponse = {
  user: AuthUserResponse;
  token: TokenResponse;
};

// 别名以兼容现有代码引用
export type RegisterResponse = AuthResponse;

export type LoginRequest =
  | {
      identifierType: IdentifierType;
      identifier: string;
      password: string;
      code?: never;
    }
  | {
      identifierType: IdentifierType;
      identifier: string;
      password?: never;
      code: string;
    };

export type LoginResponse = AuthResponse;

// 刷新令牌仅返回 TokenResponse
export type RefreshResponse = TokenResponse;

export type LogoutRequest = {
  refreshToken: string;
};

// 与 /auth/me 返回一致
export type AuthenticatedUser = AuthUserResponse;

export type ErrorResponse = {
  code: string;
  message: string;
  path?: string;
  timestamp?: string;
};
