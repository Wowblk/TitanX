import { apiFetch } from "./apiClient";
import type {
  AuthenticatedUser,
  LoginRequest,
  LoginResponse,
  LogoutRequest,
  RefreshResponse,
  RegisterRequest,
  RegisterResponse,
  SendCodeRequest,
  SendCodeResponse
} from "@/types/auth";

const AUTH_PREFIX = "/api/v1/auth";

export const authService = {
  sendCode: (payload: SendCodeRequest) =>
    apiFetch<SendCodeResponse>(`${AUTH_PREFIX}/send-code`, {
      method: "POST",
      body: payload
    }),

  register: (payload: RegisterRequest) =>
    apiFetch<RegisterResponse>(`${AUTH_PREFIX}/register`, {
      method: "POST",
      body: payload
    }),

  login: (payload: LoginRequest) =>
    apiFetch<LoginResponse>(`${AUTH_PREFIX}/login`, {
      method: "POST",
      body: payload
    }),

  logout: (payload: LogoutRequest, accessToken: string) =>
    apiFetch<void>(`${AUTH_PREFIX}/logout`, {
      method: "POST",
      body: payload,
      accessToken
    }),

  fetchCurrentUser: (accessToken: string) =>
    apiFetch<AuthenticatedUser>(`${AUTH_PREFIX}/me`, {
      accessToken
    }),

  refresh: (refreshToken: string) =>
    apiFetch<RefreshResponse>(`${AUTH_PREFIX}/token/refresh`, {
      method: "POST",
      body: { refreshToken },
      // 刷新接口不应携带（已过期的）access token
      accessToken: null
    })
};
