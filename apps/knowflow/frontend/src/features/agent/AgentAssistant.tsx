import { useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { SparkIcon } from "@/components/icons/Icon";
import { agentService } from "@/services/agentService";
import styles from "./AgentAssistant.module.css";

type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
};

const starterPrompts = [
  "帮我找一下网关相关的知文",
  "总结一下我发布过的内容",
  "帮我起草一篇关于 TitanX Agent 的知文并保存为草稿",
];

const newId = () => `${Date.now()}-${Math.random().toString(16).slice(2)}`;

const AgentAssistant = () => {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome",
      role: "assistant",
      content: "我是你的 KnowFlow AI 助手，由 TitanX Agent 驱动。可以帮你检索知识内容、整理自己的发布，也能在你明确要求时创建私有草稿。",
    },
  ]);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState("");
  const abortRef = useRef<AbortController | null>(null);
  const sessionId = useMemo(() => `knowflow-agent-${Date.now()}`, []);

  const hasPlaceholderContent = (content: string) => (
    !content.trim()
    || content === "正在思考..."
    || content === "正在检索 KnowFlow 内容..."
    || content === "已拿到工具结果，正在整理回答..."
    || content === "KnowFlow 工具调用失败，正在尝试整理可用信息..."
  );

  const send = async (text: string) => {
    const message = text.trim();
    if (!message || running) return;
    const assistantId = newId();
    setInput("");
    setMessages((prev) => [
      ...prev,
      { id: newId(), role: "user", content: message },
      { id: assistantId, role: "assistant", content: "" },
    ]);
    setRunning(true);
    setStatus("思考中");

    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 45000);
    abortRef.current = controller;
    const setAssistantContent = (content: string) => {
      setMessages((prev) => prev.map((item) => (
        item.id === assistantId ? { ...item, content } : item
      )));
    };
    try {
      await agentService.streamChat({
        sessionId,
        message,
        signal: controller.signal,
        onEvent: (event) => {
          if (event.type === "loop_start" || event.type === "iteration_start") {
            setAssistantContent("正在思考...");
          }
          if (event.type === "assistant_tool_calls") {
            setStatus("正在调用 KnowFlow 工具");
            setAssistantContent("正在检索 KnowFlow 内容...");
          }
          if (event.type === "tool_result") {
            setStatus(event.is_error ? "工具调用遇到问题" : "正在整理结果");
            setAssistantContent(event.is_error ? "KnowFlow 工具调用失败，正在尝试整理可用信息..." : "已拿到工具结果，正在整理回答...");
          }
          if (event.type === "assistant_text") {
            const text = typeof event.text === "string" ? event.text : "";
            setMessages((prev) => prev.map((item) => (
              item.id === assistantId
                ? { ...item, content: item.content.endsWith("...") || item.content.includes("正在") || item.content.includes("已拿到") ? text : `${item.content}${text}` }
                : item
            )));
          }
          if (event.type === "error") {
            const messageText = typeof event.message === "string" ? event.message : "AI 助手暂时不可用";
            setMessages((prev) => prev.map((item) => (
              item.id === assistantId
                ? { ...item, content: messageText }
                : item
            )));
          }
          if (event.type === "stream_end") {
            setMessages((prev) => prev.map((item) => (
              item.id === assistantId && hasPlaceholderContent(item.content)
                ? { ...item, content: "本轮请求已结束，但没有生成可展示的回答。请换个问法再试。" }
                : item
            )));
            setStatus("");
            setRunning(false);
            abortRef.current = null;
          }
          if (event.type === "loop_end" && event.reason && event.reason !== "completed") {
            const reasonText = event.reason === "max_iterations"
              ? "本轮工具调用次数到达上限，请换个问法再试"
              : `本轮对话结束：${String(event.reason)}`;
            setAssistantContent(reasonText);
          }
        },
      });
    } catch (error) {
      if (!controller.signal.aborted) {
        const fallback = error instanceof Error ? error.message : "AI 助手暂时不可用";
        setAssistantContent(fallback);
      } else {
        setAssistantContent("AI 助手响应超时，请稍后重试");
      }
      setStatus("");
      setRunning(false);
      abortRef.current = null;
    } finally {
      window.clearTimeout(timeoutId);
    }
  };

  const stop = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setRunning(false);
    setStatus("");
  };

  return (
    <>
      <button
        type="button"
        className={styles.fab}
        onClick={() => setOpen(true)}
        aria-label="打开 KnowFlow AI 助手"
        title="KnowFlow AI 助手"
      >
        <SparkIcon width={24} height={24} />
      </button>

      {open ? (
        <div className={styles.overlay} onMouseDown={() => setOpen(false)}>
          <section className={styles.drawer} onMouseDown={(event) => event.stopPropagation()}>
            <header className={styles.header}>
              <div>
                <div className={styles.title}>KnowFlow AI 助手</div>
                <div className={styles.subtitle}>TitanX Agent · Tool Calling</div>
              </div>
              <button type="button" className={styles.close} onClick={() => setOpen(false)} aria-label="关闭">
                ×
              </button>
            </header>

            <div className={styles.thread}>
              {messages.map((message) => (
                <div key={message.id} className={`${styles.message} ${styles[message.role]}`}>
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {message.content || (message.role === "assistant" ? "..." : " ")}
                  </ReactMarkdown>
                </div>
              ))}
            </div>

            <div className={styles.starters}>
              {starterPrompts.map((prompt) => (
                <button key={prompt} type="button" onClick={() => send(prompt)} disabled={running}>
                  {prompt}
                </button>
              ))}
            </div>

            <footer className={styles.composer}>
              {status ? <div className={styles.status}>{status}</div> : null}
              <textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder="问我任何和 KnowFlow 内容、创作、草稿有关的事"
                disabled={running}
              />
              <div className={styles.actions}>
                <button type="button" className={styles.secondary} onClick={stop} disabled={!running}>
                  停止
                </button>
                <button type="button" className={styles.primary} onClick={() => send(input)} disabled={running || !input.trim()}>
                  发送
                </button>
              </div>
            </footer>
          </section>
        </div>
      ) : null}
    </>
  );
};

export default AgentAssistant;
