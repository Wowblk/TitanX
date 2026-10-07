package com.tongji.agent.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tongji.agent.api.dto.AgentChatRequest;
import com.tongji.common.exception.BusinessException;
import com.tongji.common.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AgentGatewayService {

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Value("${agent.titanx.base-url:http://127.0.0.1:3000}")
    private String titanxBaseUrl;

    public StreamingResponseBody streamChat(AgentChatRequest request, Jwt jwt, long userId) {
        String sessionId = request.sessionId();
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = "knowflow-user-" + userId;
        }

        Map<String, Object> payload = Map.of(
                "sessionId", sessionId,
                "message", request.message(),
                "toolBearerToken", jwt.getTokenValue(),
                "userId", String.valueOf(userId)
        );

        String requestBody;
        try {
            requestBody = objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new BusinessException(ErrorCode.BAD_REQUEST, "AI 请求构造失败");
        }

        HttpRequest titanxRequest = HttpRequest.newBuilder(URI.create(titanxBaseUrl.replaceAll("/$", "") + "/api/chat"))
                .version(HttpClient.Version.HTTP_1_1)
                .timeout(Duration.ofMinutes(2))
                .header("Content-Type", "application/json")
                .header("Accept", "text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                .build();

        return outputStream -> {
            try {
                HttpResponse<InputStream> response = httpClient.send(titanxRequest, HttpResponse.BodyHandlers.ofInputStream());
                if (response.statusCode() >= 400) {
                    writeSseError(outputStream, "TitanX 网关返回异常：" + response.statusCode());
                    return;
                }
                try (InputStream inputStream = response.body()) {
                    inputStream.transferTo(outputStream);
                    outputStream.flush();
                }
            } catch (Exception e) {
                writeSseError(outputStream, "AI 助手暂时不可用，请稍后重试");
            }
        };
    }

    private void writeSseError(java.io.OutputStream outputStream, String message) throws java.io.IOException {
        String escaped = objectMapper.writeValueAsString(message);
        outputStream.write(("data: {\"type\":\"error\",\"message\":" + escaped + "}\n\n").getBytes(StandardCharsets.UTF_8));
        outputStream.write("data: {\"type\":\"stream_end\"}\n\n".getBytes(StandardCharsets.UTF_8));
        outputStream.flush();
    }
}
