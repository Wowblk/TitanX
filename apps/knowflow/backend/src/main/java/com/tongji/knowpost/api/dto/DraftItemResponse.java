package com.tongji.knowpost.api.dto;

import java.time.Instant;
import java.util.List;

/**
 * 当前用户草稿列表单条记录。
 */
public record DraftItemResponse(
        String id,
        String title,
        String description,
        String contentUrl,
        List<String> images,
        List<String> tags,
        String visible,
        String type,
        Instant createTime,
        Instant updateTime
) {}
