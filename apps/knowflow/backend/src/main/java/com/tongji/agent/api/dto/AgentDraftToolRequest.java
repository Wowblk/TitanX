package com.tongji.agent.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record AgentDraftToolRequest(
        @NotBlank String title,
        @NotBlank String content,
        String description,
        @Size(max = 20) List<String> tags
) {}
