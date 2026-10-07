package com.tongji.agent.api.dto;

import jakarta.validation.constraints.NotBlank;

public record AgentChatRequest(
        String sessionId,
        @NotBlank String message
) {}
