package com.tongji.llm.rag;

import lombok.RequiredArgsConstructor;
import com.tongji.knowpost.mapper.KnowPostMapper;
import com.tongji.knowpost.model.KnowPostDetailRow;
import com.tongji.storage.OssStorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Flux;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * RAG 问答查询服务：
 * - 在问答前保障索引，检索相关上下文并构造提示词
 * - 通过 ChatClient 以流式（SSE）方式返回模型输出
 */
@Service
@RequiredArgsConstructor
public class RagQueryService {
    private static final Logger log = LoggerFactory.getLogger(RagQueryService.class);

    // 向量检索接口（Elasticsearch 向量库封装）
    private final VectorStore vectorStore;
    // 大模型对话客户端（在 LlmConfig 中绑定 OpenAI-compatible ChatModel）
    private final ChatClient chatClient;
    // 索引服务：确保帖子在问答前已建立/更新索引
    private final RagIndexService indexService;
    private final KnowPostMapper knowPostMapper;
    private final OssStorageService storageService;
    private final RestTemplate http = new RestTemplate();

    @Value("${spring.ai.openai.chat.options.model:moonshot-v1-8k}")
    private String chatModel;

    /**
     * 使用 WebFlux 返回回答内容的流。
     */
    public Flux<String> streamAnswerFlux(long postId, String question, int topK, int maxTokens) {
        // 检索上下文：优先走向量索引；本地开发缺少 ES/Embedding 权限时，回退到当前知文正文。
        List<String> contexts = loadContexts(postId, question, Math.max(1, topK));
        if (contexts.isEmpty()) {
            return Flux.just("当前知文正文暂时不可读取，无法生成回答。");
        }
        // 组装上下文文本，分隔符用于提示词中分块标识
        String context = String.join("\n\n---\n\n", contexts);

        // 系统提示：限定只依据提供的上下文作答，无法确定需明确说明
        String system = "你是中文知识助手。只能依据提供的知文上下文回答；无法确定的请说明不确定。";
        // 用户消息：包含问题和召回到的上下文
        String user = "问题：" + question + "\n\n上下文如下（可能不完整）：\n" + context + "\n\n请基于以上上下文作答。";

        return chatClient
                .prompt() // 构建对话
                .system(system)
                .user(user)
                .options(OpenAiChatOptions.builder()
                        .model(chatModel)       // 指定 OpenAI-compatible 模型
                        .temperature(0.2)       // 低温度：更稳健、少发散
                        .maxTokens(maxTokens)    // 控制最大输出长度
                        .build())
                .stream()  // 以流式（SSE）返回模型输出
                .content(); // 转换为 Flux<String>
    }

    /**
     * 语义检索上下文：
     * - 先进行宽召回（fetchK ≥ 3×topK，至少 20）提高召回率
     * - 再按 metadata.postId 做服务端过滤，避免跨帖子污染
     */
    private List<String> searchContexts(String postId, String query, int topK) {
        int fetchK = Math.max(topK * 3, 20); // 宽召回：扩大初始检索集合
        List<Document> docs = vectorStore.similaritySearch(
                SearchRequest.builder().query(query).topK(fetchK).build() // 语义相似检索
        );
        List<String> out = new ArrayList<>(topK);
        for (Document d : docs) {
            Object pid = d.getMetadata().get("postId");
            if (pid != null && postId.equals(String.valueOf(pid))) { // 仅保留当前帖子对应的切片
                String txt = d.getText();
                if (txt != null && !txt.isEmpty()) {
                    out.add(txt);
                    if (out.size() >= topK) break; // 只取前 topK 个上下文
                }
            }
        }
        return out;
    }

    private List<String> loadContexts(long postId, String question, int topK) {
        try {
            // 轻量保障：如索引不存在或指纹未变更则跳过，否则重建
            indexService.ensureIndexed(postId);
            List<String> contexts = searchContexts(String.valueOf(postId), question, topK);
            if (!contexts.isEmpty()) {
                return contexts;
            }
        } catch (Exception e) {
            log.warn("RAG vector search unavailable for post {}: {}", postId, e.getMessage());
        }
        return loadLocalPostContent(postId, topK);
    }

    private List<String> loadLocalPostContent(long postId, int topK) {
        KnowPostDetailRow row = knowPostMapper.findDetailById(postId);
        if (row == null
                || !"published".equalsIgnoreCase(row.getStatus())
                || !"public".equalsIgnoreCase(row.getVisible())
                || !StringUtils.hasText(row.getContentUrl())) {
            return List.of();
        }

        String text = readContent(row.getContentUrl());
        if (!StringUtils.hasText(text)) {
            return List.of();
        }

        List<String> chunks = chunkText(text);
        return chunks.subList(0, Math.min(chunks.size(), topK));
    }

    private String readContent(String contentUrl) {
        try {
            if (contentUrl.startsWith("/api/v1/storage/local-files?")) {
                String objectKey = extractQueryParam(contentUrl, "objectKey");
                if (StringUtils.hasText(objectKey)) {
                    return Files.readString(storageService.resolveLocalObject(objectKey), StandardCharsets.UTF_8);
                }
            }
            if (contentUrl.startsWith("http://") || contentUrl.startsWith("https://")) {
                return http.getForObject(contentUrl, String.class);
            }
        } catch (Exception e) {
            log.warn("Read post content failed url={}: {}", contentUrl, e.getMessage());
        }
        return null;
    }

    private String extractQueryParam(String url, String name) {
        int question = url.indexOf('?');
        if (question < 0 || question == url.length() - 1) {
            return null;
        }
        String[] pairs = url.substring(question + 1).split("&");
        for (String pair : pairs) {
            int equals = pair.indexOf('=');
            if (equals <= 0) {
                continue;
            }
            String key = URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8);
            if (name.equals(key)) {
                return URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private List<String> chunkText(String text) {
        List<String> chunks = new ArrayList<>();
        int start = 0;
        while (start < text.length()) {
            int end = Math.min(start + 1600, text.length());
            chunks.add(text.substring(start, end));
            if (end >= text.length()) {
                break;
            }
            start = Math.max(end - 120, start + 1);
        }
        return chunks;
    }
}
