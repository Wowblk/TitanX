package com.tongji.agent.service;

import com.tongji.agent.api.dto.AgentDraftToolRequest;
import com.tongji.agent.api.dto.AgentDraftToolResponse;
import com.tongji.knowpost.service.KnowPostService;
import com.tongji.storage.OssStorageService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AgentToolService {

    private final KnowPostService knowPostService;
    private final OssStorageService ossStorageService;

    @Transactional
    public AgentDraftToolResponse createDraft(long userId, AgentDraftToolRequest request) {
        long draftId = knowPostService.createDraft(userId);
        byte[] bytes = request.content().getBytes(StandardCharsets.UTF_8);
        String objectKey = "agent-drafts/" + userId + "/" + draftId + "-" + Instant.now().toEpochMilli() + ".md";
        String etag = ossStorageService.saveLocalObject(objectKey, new ByteArrayInputStream(bytes));
        String sha256 = sha256(bytes);

        knowPostService.confirmContent(userId, draftId, objectKey, etag, (long) bytes.length, sha256);
        knowPostService.updateMetadata(
                userId,
                draftId,
                request.title(),
                null,
                request.tags() == null ? List.of() : request.tags(),
                List.of(),
                "private",
                false,
                request.description()
        );
        return new AgentDraftToolResponse(String.valueOf(draftId), ossStorageService.publicUrl(objectKey));
    }

    private String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
