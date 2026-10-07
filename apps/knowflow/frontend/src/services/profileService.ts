import { apiFetch } from "./apiClient";
import type { ProfileResponse, ProfileUpdateRequest } from "@/types/profile";

const PROFILE_PREFIX = "/api/v1/profile";

export const profileService = {
  update: (payload: ProfileUpdateRequest) =>
    apiFetch<ProfileResponse>(`${PROFILE_PREFIX}`, {
      method: "PATCH",
      body: payload
    }),

  uploadAvatar: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return apiFetch<ProfileResponse>(`${PROFILE_PREFIX}/avatar`, {
      method: "POST",
      body: form
    });
  }
};