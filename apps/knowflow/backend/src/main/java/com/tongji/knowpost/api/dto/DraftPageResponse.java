package com.tongji.knowpost.api.dto;

import java.util.List;

/**
 * 当前用户草稿分页响应。
 */
public record DraftPageResponse(
        List<DraftItemResponse> items,
        int page,
        int size,
        boolean hasMore
) {}
