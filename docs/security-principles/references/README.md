# 官方资料与版本记录

核验日期：2026-09-10。仅使用 OWASP 官方来源。版本年份与发布日期分别记录，
不因网页最近更新就把旧版条目改称新版。

## 主要参考：Agentic Applications Top 10 2026

- 发布方：OWASP Gen AI Security Project / Agentic Security Initiative。
- [官方资源页](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)。
- [官方 PDF 下载入口](https://genai.owasp.org/download/52117/?tmstv=1765059207)。
- 版本：2026；资源页日期：2025-12-09；PDF 封面日期：December 2025。
- 本次已通过网页读取核对 PDF 的版本、57 页页数及目录 ASI01 至 ASI10。
- 用途：TitanX 的工具执行、权限、上下文、恢复及未来委派设计的主要风险参考。

项目原则中的 ASI 编号均指这一版本。编号关联是 TitanX 的工程映射，
没有表达每条项目原则足以单独缓解对应类别的全部风险。

## 补充参考：LLM Top 10 2026

- 发布方：OWASP Gen AI Security Project。
- [官方资源页](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)。
- [官方 PDF 下载入口](https://genai.owasp.org/download/56857/?tmstv=1785822482)。
- 版本：2026；资源页日期：2026-08-03。
- 本次已核对官方资源页的标题、日期和下载入口；PDF 下载未成功，未逐项核对正文。
- 用途：补充 LLM 应用层的风险审查；取得正文后再补充该版本的逐条编号映射。

本目录不沿用 2025 年的 `LLMxx` 编号来推断 2026 年排名或条目。

## 历史参考：Excessive Agency 2025

[LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
保留为[原安全设计](../../model-tool-loop-security-design.md)的历史引用。
该链接明确属于 2025 版，不作为 2026 版条目编号的证据。

## 本地原文与使用说明

本轮下载两份资料时，本地请求返回了 HTML 的 “No Access” 页面，没有得到有效 PDF；
因此本目录保存官方入口，没有把错误页作为 PDF 入库。网页工具能够读取 Agentic 原文，
LLM 原文读取超时。上述差异不影响已核验的资源页版本记录。

后续保留本地原文时，先核对 PDF 文件格式、封面、版本及授权说明，再记录文件名、
来源、下载日期和 SHA-256。保持原文不变；修订版另存，注明变更。

Agentic PDF 的授权页标注 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)；
OWASP 资源页也提供站点内容的许可说明。转载或翻译时保留项目名称、资料名称、来源和
许可，按原文要求标注修改。这里的工程原则是项目整理，未经 OWASP 审核或背书。

资料引用不改变 TitanX 源码的现有许可证。
